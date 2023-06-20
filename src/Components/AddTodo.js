import React, { useState } from "react";

const AddTodo = (props) => {
  const [title, settitle] = useState("");

  const [desc, setdesc] = useState("");

  const submitHandler = (e) => {

    e.preventDefault();

   props.addTodo(title, desc); 
   settitle("");
   setdesc("");
  };
  return (
    <div className="container my-3">
      <h3>Add Todos</h3>
      <form onSubmit={submitHandler}>
        <div className="form-group">
          <label htmlFor="title">Todo Title</label>
          <input
            type="text"
            className="form-control"
            id="title"
            value={title}
            onChange={(e) => {
              settitle(e.target.value);
            }}
            placeholder="Enter Title"
          />
        </div>
        <div className="form-group">
          <label htmlFor="desc">Description</label>
          <input
            type="text"
            className="form-control"
            id="desc"
            value={desc}
            onChange={(e) => {
              setdesc(e.target.value);
            }}
            placeholder="Enter Description"
          />
        </div>

        <button type="submit" className="btn btn-sm btn-success my-2">
          Submit
        </button>
        <hr/>
      </form>
    </div>
  );
};

export default AddTodo;
