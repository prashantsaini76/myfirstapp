"""Enterprise Log Analyzer - Streamlit dashboard for request/response logs."""
from __future__ import annotations

import bisect
import io
import json
import re
from datetime import datetime
from typing import Any

TS_BRACKET_RE = re.compile(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\]")

import pandas as pd
import requests
import streamlit as st

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LINE_RE = re.compile(
    r"^\[(?P<ts>[^\]]+)\]\s+"
    r"\[(?P<api>[^\]]+)\]\s+"
    r"\[(?P<log_type>[^\]]+)\]\s+"
    r"\[(?P<component>[^\]]+)\]\s+"
    r"\[(?P<mdc>[^\]]*)\]\s*-\s*(?P<desc>.*)$"
)

REQ_MARK = "::RECEIVED-REQUEST::"
REQ_END = "::END-OF-REQUEST::"
RESP_MARK = "::RETURNED-RESPONSE::"
RESP_END = "::END-OF-RESPONSE::"

REMOVED_HEADERS = {"vinzauthorization", "singularityheader"}
HARDCODED_AUTH = ("Authorization", "Bearer <your token>")

TS_FORMATS = ["%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"]


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------

def read_uploaded_file(uploaded) -> str:
    if uploaded is None:
        return ""
    data = uploaded.read()
    if isinstance(data, bytes):
        for enc in ("utf-8", "latin-1"):
            try:
                return data.decode(enc)
            except UnicodeDecodeError:
                continue
        return data.decode("utf-8", errors="replace")
    return str(data)


def fetch_log_from_url(url: str, verify_ssl: bool = True, timeout: int = 60) -> str:
    """Stream the response so 100 MB downloads don't hang the UI."""
    progress = st.progress(0.0, text="Connecting...")
    status = st.empty()
    chunks: list[bytes] = []
    downloaded = 0
    try:
        with requests.get(url, verify=verify_ssl, timeout=timeout, stream=True) as resp:
            resp.raise_for_status()
            total = int(resp.headers.get("Content-Length") or 0)
            for chunk in resp.iter_content(chunk_size=1 << 20):  # 1 MB
                if not chunk:
                    continue
                chunks.append(chunk)
                downloaded += len(chunk)
                if total:
                    progress.progress(min(downloaded / total, 1.0),
                                      text=f"Downloaded {downloaded/1e6:.1f} / {total/1e6:.1f} MB")
                else:
                    status.text(f"Downloaded {downloaded/1e6:.1f} MB")
    finally:
        progress.empty()
        status.empty()
    data = b"".join(chunks)
    for enc in ("utf-8", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_ts(s: str) -> datetime | None:
    s = s.strip()
    for fmt in TS_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def pretty_json(value: Any) -> str:
    """Best-effort pretty JSON. Handles escaped JSON strings and dict-like text."""
    if value is None or value == "":
        return ""
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, indent=2, ensure_ascii=False)
        except (TypeError, ValueError):
            return str(value)
    if not isinstance(value, str):
        return str(value)
    s = value.strip()
    if not s:
        return ""
    candidates = [s]
    if "\\\"" in s or "\\\\" in s:
        try:
            candidates.append(json.loads(f'"{s}"'))
        except (json.JSONDecodeError, ValueError):
            pass
        candidates.append(s.replace('\\"', '"').replace("\\\\", "\\"))
    for c in candidates:
        try:
            obj = json.loads(c)
            return json.dumps(obj, indent=2, ensure_ascii=False)
        except (json.JSONDecodeError, TypeError):
            continue
    return value


# ---------------------------------------------------------------------------
# Header parsing
# ---------------------------------------------------------------------------

def parse_headers(headers_str: str) -> dict[str, str]:
    """Parse `key1=[val1], key2=[val2], ...` allowing brackets/commas inside values."""
    out: dict[str, str] = {}
    if not headers_str:
        return out
    s = headers_str.strip()
    i, n = 0, len(s)
    while i < n:
        eq = s.find("=[", i)
        if eq == -1:
            break
        key = s[i:eq].strip().lstrip(",").strip()
        j = eq + 2
        depth = 1
        buf = []
        while j < n and depth > 0:
            ch = s[j]
            if ch == "[":
                depth += 1
                buf.append(ch)
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    break
                buf.append(ch)
            else:
                buf.append(ch)
            j += 1
        val = "".join(buf)
        if key:
            out[key] = val
        i = j + 1
        while i < n and s[i] in ", ":
            i += 1
    return out


def clean_headers(headers: dict[str, str]) -> dict[str, str]:
    cleaned = {k: v for k, v in headers.items() if k.lower() not in REMOVED_HEADERS}
    cleaned[HARDCODED_AUTH[0]] = HARDCODED_AUTH[1]
    return cleaned


# ---------------------------------------------------------------------------
# Request / Response extraction
# ---------------------------------------------------------------------------

def extract_request_fields(block_text: str) -> dict[str, Any]:
    """Pull uri, method, headers dict, raw payload from a RECEIVED-REQUEST segment."""
    result = {"uri": "", "method": "", "headers": {}, "request_payload": ""}
    start = block_text.find(REQ_MARK)
    end = block_text.find(REQ_END)
    if start == -1:
        return result
    segment = block_text[start + len(REQ_MARK): end if end != -1 else len(block_text)]

    m = re.search(r"uri=(.*?);method=", segment, re.DOTALL)
    if m:
        result["uri"] = m.group(1).strip()
    m = re.search(r"method=([^;]+);", segment)
    if m:
        result["method"] = m.group(1).strip()

    h_start = segment.find("headers={")
    if h_start != -1:
        i = h_start + len("headers={")
        depth = 1
        j = i
        while j < len(segment) and depth > 0:
            ch = segment[j]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        headers_raw = segment[i:j]
        result["headers"] = parse_headers(headers_raw)

    p = re.search(r"payload=(.*)$", segment, re.DOTALL)
    if p:
        result["request_payload"] = p.group(1).strip()
    return result


def extract_response_fields(block_text: str) -> dict[str, Any]:
    result = {"response_payload": "", "http_status": "", "response_headers": {}}
    start = block_text.find(RESP_MARK)
    end = block_text.find(RESP_END)
    if start == -1:
        return result
    segment = block_text[start + len(RESP_MARK): end if end != -1 else len(block_text)]

    m = re.search(r"HTTP STATUS=([^;]+);", segment)
    if m:
        result["http_status"] = m.group(1).strip()

    h_start = segment.find("headers={")
    if h_start != -1:
        i = h_start + len("headers={")
        depth = 1
        j = i
        while j < len(segment) and depth > 0:
            ch = segment[j]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        result["response_headers"] = parse_headers(segment[i:j])

    p = re.search(r"payload=(.*)$", segment, re.DOTALL)
    if p:
        result["response_payload"] = p.group(1).strip()
    return result


# ---------------------------------------------------------------------------
# Top-level parsing
# ---------------------------------------------------------------------------

def parse_log_line(line: str) -> dict[str, Any] | None:
    m = LINE_RE.match(line)
    if not m:
        return None
    return {
        "timestamp": m.group("ts").strip(),
        "api": m.group("api").strip(),
        "log_type": m.group("log_type").strip(),
        "component": m.group("component").strip(),
        "description": m.group("desc").strip(),
    }


def _flush_block(lines: list[str]) -> str:
    return "\n".join(lines).strip()


def parse_transactions(text: str) -> tuple[list[dict], list[dict]]:
    """Return (log_lines, transactions).

    Single-pass O(N) implementation. Uses line indices instead of substring
    membership for correlation_id backfill so 100 MB files parse in seconds.
    """
    raw_lines = text.split("\n")
    n = len(raw_lines)

    # Pass 1: locate block boundaries by line index.
    block_ranges: list[tuple[int, int]] = []
    cur_start: int | None = None
    for i in range(n):
        ln = raw_lines[i]
        if REQ_MARK in ln:
            if cur_start is not None:
                block_ranges.append((cur_start, i - 1))
            cur_start = i
        elif cur_start is not None and RESP_END in ln:
            block_ranges.append((cur_start, i))
            cur_start = None
    if cur_start is not None:
        block_ranges.append((cur_start, n - 1))

    # Pass 2: parse log lines (only lines matching LINE_RE become rows).
    log_rows: list[dict] = []
    for i in range(n):
        ln = raw_lines[i]
        # quick reject: real log lines must start with "[" and a digit
        if not ln or ln[0] != "[":
            continue
        parsed = parse_log_line(ln)
        if parsed:
            parsed["line_idx"] = i
            parsed["correlation_id"] = None
            log_rows.append(parsed)

    # Pass 3: finalize each transaction.
    txns: list[dict] = []
    for bi, (s, e) in enumerate(block_ranges):
        block_text = "\n".join(raw_lines[s:e + 1])
        first_parsed = parse_log_line(raw_lines[s]) if raw_lines[s].startswith("[") else None

        req = extract_request_fields(block_text)
        resp = extract_response_fields(block_text)
        headers = req["headers"]
        correlation_id = (
            headers.get("correlation-id")
            or headers.get("Correlation-Id")
            or f"txn-{bi + 1:06d}"
        )
        channel = headers.get("channel-id") or headers.get("requestsystemname") or ""

        first_ts = parse_ts(first_parsed["timestamp"]) if first_parsed else None
        last_ts = None
        for m in TS_BRACKET_RE.finditer(block_text):
            last_ts = parse_ts(m.group(1))
        duration_ms: Any = ""
        if first_ts and last_ts:
            duration_ms = int((last_ts - first_ts).total_seconds() * 1000)

        txns.append({
            "correlation_id": correlation_id,
            "timestamp": first_parsed["timestamp"] if first_parsed else "",
            "api": first_parsed["api"] if first_parsed else "",
            "component": first_parsed["component"] if first_parsed else "",
            "uri": req["uri"],
            "method": req["method"],
            "channel": channel,
            "http_status": resp["http_status"],
            "duration_ms": duration_ms,
            "headers": json.dumps(clean_headers(headers), indent=2, ensure_ascii=False),
            "request_payload": pretty_json(req["request_payload"]) or "",
            "response_payload": pretty_json(resp["response_payload"]) or "",
            "full_raw_block": block_text,
        })

    # Pass 4: backfill correlation_id on log lines using bisect (O(N log T)).
    starts = [b[0] for b in block_ranges]
    ends = [b[1] for b in block_ranges]
    for row in log_rows:
        idx = row["line_idx"]
        pos = bisect.bisect_right(starts, idx) - 1
        if pos >= 0 and starts[pos] <= idx <= ends[pos]:
            row["correlation_id"] = txns[pos]["correlation_id"]

    return log_rows, txns


# ---------------------------------------------------------------------------
# Dataframes
# ---------------------------------------------------------------------------

def build_transaction_dataframe(txns: list[dict]) -> pd.DataFrame:
    cols = [
        "correlation_id", "timestamp", "api", "uri", "method", "channel",
        "http_status", "duration_ms", "component", "headers",
        "request_payload", "response_payload", "full_raw_block",
    ]
    if not txns:
        return pd.DataFrame(columns=cols)
    df = pd.DataFrame(txns)
    for c in cols:
        if c not in df.columns:
            df[c] = ""
    return df[cols]


def build_logline_dataframe(rows: list[dict]) -> pd.DataFrame:
    cols = ["timestamp", "api", "log_type", "component", "correlation_id", "description"]
    if not rows:
        return pd.DataFrame(columns=cols)
    df = pd.DataFrame(rows)
    for c in cols:
        if c not in df.columns:
            df[c] = ""
    return df[cols]


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

SEARCH_FIELDS = [
    "correlation_id", "api", "component", "uri", "method", "channel",
    "headers", "request_payload", "response_payload", "description",
    "full_raw_block",
]


def _keyword_mask(df: pd.DataFrame, keyword: str) -> pd.Series:
    """Vectorized OR-across-columns substring search."""
    kw = keyword.lower()
    mask = pd.Series(False, index=df.index)
    for f in SEARCH_FIELDS:
        if f not in df.columns:
            continue
        col = df[f].astype(str).str.lower()
        mask |= col.str.contains(kw, regex=False, na=False)
    return mask


def apply_filters(df: pd.DataFrame, filters: dict) -> pd.DataFrame:
    if df.empty:
        return df
    out = df

    keyword = (filters.get("keyword") or "").strip()
    if keyword:
        out = out[_keyword_mask(out, keyword)]

    for col in ("correlation_id", "api", "log_type", "component", "uri", "method", "channel", "http_status"):
        val = filters.get(col)
        if val:
            if isinstance(val, list):
                if val:
                    out = out[out[col].astype(str).isin([str(v) for v in val])]
            else:
                out = out[out[col].astype(str).str.contains(str(val), case=False, na=False)]

    ts_range = filters.get("ts_range")
    if ts_range and "timestamp" in out.columns:
        start, end = ts_range
        ts_series = pd.to_datetime(out["timestamp"], errors="coerce")
        if start:
            out = out[ts_series >= pd.Timestamp(start)]
            ts_series = pd.to_datetime(out["timestamp"], errors="coerce")
        if end:
            out = out[ts_series <= pd.Timestamp(end)]

    dur_range = filters.get("duration_range")
    if dur_range and "duration_ms" in out.columns:
        lo, hi = dur_range
        d = pd.to_numeric(out["duration_ms"], errors="coerce")
        if lo is not None:
            out = out[d >= lo]
            d = pd.to_numeric(out["duration_ms"], errors="coerce")
        if hi is not None:
            out = out[d <= hi]

    # Section-specific keyword searches
    for section in ("headers", "request_payload", "response_payload"):
        key = filters.get(f"{section}_search")
        if key and section in out.columns:
            out = out[out[section].astype(str).str.contains(key, case=False, na=False)]

    # Advanced filter builder (vectorized: combine per-rule masks).
    adv = filters.get("advanced")
    if adv:
        rules = adv.get("rules", [])
        logic = adv.get("logic", "AND").upper()
        if rules:
            combined: pd.Series | None = None
            for r in rules:
                field = r.get("field")
                op = r.get("op", "contains")
                val = r.get("value", "")
                if field not in out.columns:
                    rule_mask = pd.Series(False, index=out.index)
                else:
                    cell = out[field].astype(str)
                    cell_l = cell.str.lower()
                    v_l = val.lower()
                    if op == "equals":
                        rule_mask = cell_l == v_l
                    elif op == "not_equals":
                        rule_mask = cell_l != v_l
                    elif op == "contains":
                        rule_mask = cell_l.str.contains(v_l, regex=False, na=False)
                    elif op == "not_contains":
                        rule_mask = ~cell_l.str.contains(v_l, regex=False, na=False)
                    elif op == "regex":
                        try:
                            rule_mask = cell.str.contains(val, regex=True, na=False)
                        except re.error:
                            rule_mask = pd.Series(False, index=out.index)
                    else:
                        rule_mask = pd.Series(True, index=out.index)
                if combined is None:
                    combined = rule_mask
                else:
                    combined = (combined & rule_mask) if logic == "AND" else (combined | rule_mask)
            if combined is not None:
                out = out[combined]

    return out


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _safe_metric(label: str, value: Any) -> None:
    st.metric(label, "-" if value in ("", None) else value)


def render_kpis(txn_df: pd.DataFrame, line_df: pd.DataFrame) -> None:
    total_lines = len(line_df)
    total_txns = len(txn_df)
    unique_cid = txn_df["correlation_id"].nunique() if not txn_df.empty else 0
    total_apis = txn_df["api"].nunique() if not txn_df.empty else 0

    status_series = pd.to_numeric(txn_df["http_status"], errors="coerce") if not txn_df.empty else pd.Series([], dtype=float)
    error_count = int((status_series.fillna(0) >= 400).sum()) if not txn_df.empty else 0

    dur_series = pd.to_numeric(txn_df["duration_ms"], errors="coerce") if not txn_df.empty else pd.Series([], dtype=float)
    avg_dur = round(dur_series.dropna().mean(), 2) if not dur_series.dropna().empty else 0
    slowest = int(dur_series.dropna().max()) if not dur_series.dropna().empty else 0

    top_api = txn_df["api"].mode().iat[0] if not txn_df.empty and not txn_df["api"].mode().empty else ""
    top_uri = txn_df["uri"].mode().iat[0] if not txn_df.empty and not txn_df["uri"].mode().empty else ""
    top_status = txn_df["http_status"].mode().iat[0] if not txn_df.empty and not txn_df["http_status"].mode().empty else ""

    c1, c2, c3, c4, c5 = st.columns(5)
    with c1: _safe_metric("Total log lines", total_lines)
    with c2: _safe_metric("Total transactions", total_txns)
    with c3: _safe_metric("Unique correlation IDs", unique_cid)
    with c4: _safe_metric("Total APIs", total_apis)
    with c5: _safe_metric("Errors (>=400)", error_count)

    c6, c7, c8, c9, c10 = st.columns(5)
    with c6: _safe_metric("Avg duration (ms)", avg_dur)
    with c7: _safe_metric("Slowest (ms)", slowest)
    with c8: _safe_metric("Top API", top_api)
    with c9: _safe_metric("Top URI", top_uri)
    with c10: _safe_metric("Top HTTP status", top_status)


def render_overview(txn_df: pd.DataFrame, line_df: pd.DataFrame) -> None:
    render_kpis(txn_df, line_df)
    if txn_df.empty:
        st.info("No transactions parsed yet.")
        return

    col_a, col_b = st.columns(2)
    with col_a:
        st.subheader("HTTP status distribution")
        s = txn_df["http_status"].replace("", pd.NA).dropna().value_counts()
        if not s.empty:
            st.bar_chart(s)
        else:
            st.caption("No HTTP status values found.")

        st.subheader("API-wise transaction count")
        a = txn_df["api"].replace("", pd.NA).dropna().value_counts()
        if not a.empty:
            st.bar_chart(a)

    with col_b:
        st.subheader("Slowest transactions")
        dur = pd.to_numeric(txn_df["duration_ms"], errors="coerce")
        slow = txn_df.assign(_d=dur).sort_values("_d", ascending=False).head(10)
        st.dataframe(
            slow[["correlation_id", "api", "uri", "method", "http_status", "duration_ms"]],
            use_container_width=True, hide_index=True,
        )

        st.subheader("Top URIs")
        u = txn_df["uri"].replace("", pd.NA).dropna().value_counts().head(10).rename_axis("uri").reset_index(name="count")
        st.dataframe(u, use_container_width=True, hide_index=True)

        st.subheader("Top components")
        c = txn_df["component"].replace("", pd.NA).dropna().value_counts().head(10).rename_axis("component").reset_index(name="count")
        st.dataframe(c, use_container_width=True, hide_index=True)


def render_transactions(txn_df: pd.DataFrame) -> None:
    if txn_df.empty:
        st.info("No transactions to display.")
        return
    summary_cols = ["correlation_id", "timestamp", "api", "uri", "method", "channel", "http_status", "duration_ms"]

    # Header row: count + inline export. CSV excludes the multi-MB raw block
    # column so generation is near-instant even on 100 MB inputs.
    head_l, head_r = st.columns([3, 1])
    with head_l:
        st.caption(f"{len(txn_df):,} transactions")
    with head_r:
        st.download_button(
            "Download CSV",
            data=txn_df[summary_cols + ["component"]].to_csv(index=False).encode("utf-8"),
            file_name="transactions.csv",
            mime="text/csv",
            use_container_width=True,
        )

    st.dataframe(txn_df[summary_cols], use_container_width=True, hide_index=True)

    st.markdown("### Inspect transaction")
    cid = st.selectbox("Select correlation_id", txn_df["correlation_id"].tolist(), key="txn_inspect")
    row = txn_df[txn_df["correlation_id"] == cid].iloc[0]

    with st.expander("Headers (cleaned JSON)", expanded=False):
        st.code(row["headers"], language="json")
    with st.expander("Request payload", expanded=False):
        st.code(row["request_payload"] or "(empty)", language="json")
    with st.expander("Response payload", expanded=False):
        st.code(row["response_payload"] or "(empty)", language="json")
    with st.expander("Raw block", expanded=False):
        st.code(row["full_raw_block"], language="text")
        st.download_button(
            "Download this transaction (TXT)",
            data=row["full_raw_block"].encode("utf-8"),
            file_name=f"{cid}.txt",
            mime="text/plain",
            key="dl_raw_txt",
        )


def render_log_lines(line_df: pd.DataFrame) -> None:
    if line_df.empty:
        st.info("No log lines parsed.")
        return
    q = st.text_input("Search log lines", key="line_search")
    df = line_df
    if q:
        kw = q.lower()
        mask = pd.Series(False, index=df.index)
        for c in df.columns:
            mask |= df[c].astype(str).str.lower().str.contains(kw, regex=False, na=False)
        df = df[mask]

    MAX_ROWS = 5000
    total = len(df)

    head_l, head_r = st.columns([3, 1])
    with head_l:
        if total > MAX_ROWS:
            st.caption(f"Showing first {MAX_ROWS:,} of {total:,} rows. Refine the search to narrow down.")
        else:
            st.caption(f"{total:,} rows")
    with head_r:
        # Export the full filtered set (not just the displayed slice).
        st.download_button(
            "Download CSV",
            data=df.to_csv(index=False).encode("utf-8"),
            file_name="log_lines.csv",
            mime="text/csv",
            use_container_width=True,
            disabled=df.empty,
        )

    st.dataframe(df.head(MAX_ROWS), use_container_width=True, hide_index=True)


def render_payload_viewer(txn_df: pd.DataFrame) -> None:
    if txn_df.empty:
        st.info("No transactions available.")
        return
    cid = st.selectbox("Select correlation_id", txn_df["correlation_id"].tolist(), key="payload_cid")
    row = txn_df[txn_df["correlation_id"] == cid].iloc[0]
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Request payload")
        st.code(row["request_payload"] or "(empty)", language="json")
    with col2:
        st.subheader("Response payload")
        st.code(row["response_payload"] or "(empty)", language="json")


def render_header_viewer(txn_df: pd.DataFrame) -> None:
    if txn_df.empty:
        st.info("No transactions available.")
        return
    cid = st.selectbox("Select correlation_id", txn_df["correlation_id"].tolist(), key="hdr_cid")
    row = txn_df[txn_df["correlation_id"] == cid].iloc[0]
    st.code(row["headers"], language="json")


# ---------------------------------------------------------------------------
# Sidebar filters
# ---------------------------------------------------------------------------

def sidebar_filters(txn_df: pd.DataFrame) -> dict:
    st.sidebar.header("Filters")
    filters: dict = {}
    filters["keyword"] = st.sidebar.text_input("Global keyword search")

    with st.sidebar.expander("Column filters", expanded=False):
        if not txn_df.empty:
            filters["correlation_id"] = st.text_input("correlation_id contains")
            filters["api"] = st.multiselect("api", sorted(txn_df["api"].dropna().unique().tolist()))
            filters["component"] = st.text_input("component contains")
            filters["uri"] = st.text_input("uri contains")
            filters["method"] = st.multiselect("method", sorted(txn_df["method"].dropna().unique().tolist()))
            filters["channel"] = st.multiselect("channel", sorted(txn_df["channel"].dropna().unique().tolist()))
            filters["http_status"] = st.multiselect("http_status", sorted(txn_df["http_status"].dropna().astype(str).unique().tolist()))

            tsa, tsb = st.columns(2)
            with tsa:
                start_date = st.date_input("From date", value=None, key="from_date")
            with tsb:
                end_date = st.date_input("To date", value=None, key="to_date")
            filters["ts_range"] = (start_date, end_date)

            dur_series = pd.to_numeric(txn_df["duration_ms"], errors="coerce").dropna()
            if not dur_series.empty:
                lo, hi = int(dur_series.min()), int(dur_series.max())
                if lo == hi:
                    hi = lo + 1
                rng = st.slider("duration_ms", lo, hi, (lo, hi))
                filters["duration_range"] = rng

    with st.sidebar.expander("Section search", expanded=False):
        filters["headers_search"] = st.text_input("Search in headers")
        filters["request_payload_search"] = st.text_input("Search in request payload")
        filters["response_payload_search"] = st.text_input("Search in response payload")

    with st.sidebar.expander("Advanced filter builder", expanded=False):
        logic = st.radio("Combine with", ["AND", "OR"], horizontal=True, key="adv_logic")
        n = st.number_input("Number of rules", 0, 8, 0, step=1, key="adv_n")
        rules = []
        fields = ["correlation_id", "api", "component", "uri", "method", "channel",
                  "http_status", "headers", "request_payload", "response_payload", "description"]
        ops = ["contains", "not_contains", "equals", "not_equals", "regex"]
        for i in range(int(n)):
            c1, c2, c3 = st.columns([2, 2, 3])
            with c1:
                f = st.selectbox(f"Field {i+1}", fields, key=f"adv_f_{i}")
            with c2:
                o = st.selectbox(f"Op {i+1}", ops, key=f"adv_o_{i}")
            with c3:
                v = st.text_input(f"Value {i+1}", key=f"adv_v_{i}")
            if v != "":
                rules.append({"field": f, "op": o, "value": v})
        filters["advanced"] = {"logic": logic, "rules": rules}

    return filters


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _load_text() -> str | None:
    """Render the input UI inside a collapsible expander.

    Returns the raw text exactly once - on the rerun when the user clicked
    "Load & Parse" - otherwise None.
    """
    already_loaded = "txn_df" in st.session_state
    with st.expander("Load logs", expanded=not already_loaded):
        mode = st.radio(
            "Source",
            ["Upload Log File", "Paste Log Content", "Fetch From URL"],
            horizontal=True,
            key="input_mode",
        )
        upload_obj = None
        paste_text = ""
        url = ""
        bypass = False

        if mode == "Upload Log File":
            upload_obj = st.file_uploader("Choose .log or .txt", type=["log", "txt"])
        elif mode == "Paste Log Content":
            paste_text = st.text_area("Paste log content", height=240, key="paste_text")
        else:
            url = st.text_input("Log URL", placeholder="https://example.com/app.log", key="log_url")
            bypass = st.checkbox("Bypass SSL/certificate verification (verify=False)", key="ssl_bypass")
            if bypass:
                st.warning("SSL verification is disabled. Use only with trusted internal endpoints.")

        col_p, col_c = st.columns([1, 1])
        with col_p:
            action_clicked = st.button("Load & Parse", type="primary", use_container_width=True)
        with col_c:
            if st.button("Clear / Reset", use_container_width=True):
                for k in ("txn_df", "line_df"):
                    st.session_state.pop(k, None)
                st.rerun()

    if not action_clicked:
        return None

    # Single click handles both fetch (if URL) and read (if upload), then parse.
    if mode == "Upload Log File":
        if upload_obj is None:
            st.error("Choose a file first.")
            return None
        return read_uploaded_file(upload_obj)

    if mode == "Paste Log Content":
        if not paste_text.strip():
            st.error("Paste log content first.")
            return None
        return paste_text

    # URL mode
    if not url.strip():
        st.error("Enter a URL first.")
        return None
    try:
        return fetch_log_from_url(url, verify_ssl=not bypass)
    except requests.RequestException as e:
        st.error(f"Fetch failed: {e}")
    except Exception as e:
        st.error(f"Unexpected error: {e}")
    return None


def main() -> None:
    st.set_page_config(page_title="API Log Viewer", layout="wide")
    st.markdown(
        """
        <style>
        [data-testid="stMetricValue"] { font-size: 1.25rem; white-space: normal; word-break: break-word; line-height: 1.2; }
        [data-testid="stMetricLabel"] { font-size: 0.8rem; }
        </style>
        """,
        unsafe_allow_html=True,
    )
    st.title("API Log Viewer")
    st.caption(
        "Parses request/response transaction logs and helps investigate transactions "
        "by correlation_id."
    )

    text_to_parse = _load_text()

    if text_to_parse:
        size_mb = len(text_to_parse) / 1e6
        with st.spinner(f"Parsing {size_mb:.1f} MB..."):
            t0 = datetime.now()
            try:
                log_rows, txns = parse_transactions(text_to_parse)
            except Exception as e:
                st.error(f"Parsing failed: {e}")
                return
            st.session_state["txn_df"] = build_transaction_dataframe(txns)
            st.session_state["line_df"] = build_logline_dataframe(log_rows)
            elapsed = (datetime.now() - t0).total_seconds()
            st.success(
                f"Parsed {size_mb:.1f} MB in {elapsed:.1f}s - "
                f"{len(log_rows):,} log lines, {len(txns):,} transactions."
            )

    txn_df = st.session_state.get("txn_df")
    line_df = st.session_state.get("line_df")

    if txn_df is None or line_df is None:
        st.info("Provide logs via upload, paste, or URL fetch, then click Parse.")
        return

    filters = sidebar_filters(txn_df)
    f_txn = apply_filters(txn_df, filters)
    f_line = apply_filters(line_df, {
        "keyword": filters.get("keyword", ""),
        "api": filters.get("api"),
        "log_type": filters.get("log_type"),
        "component": filters.get("component"),
        "correlation_id": filters.get("correlation_id"),
        "ts_range": filters.get("ts_range"),
        "advanced": filters.get("advanced"),
    })

    # Radio-as-tabs persists the active view across reruns (st.tabs resets
    # to the first tab whenever a child widget like a selectbox changes).
    views = ["Overview", "Transactions", "Log Lines"]
    view = st.radio("View", views, horizontal=True, key="active_view",
                    label_visibility="collapsed")
    st.divider()

    if view == "Overview":
        render_overview(f_txn, f_line)
    elif view == "Transactions":
        render_transactions(f_txn)
    elif view == "Log Lines":
        render_log_lines(f_line)


# Note: to allow >200 MB uploads, run with:
#   streamlit run app.py --server.maxUploadSize 500
if __name__ == "__main__":
    main()
