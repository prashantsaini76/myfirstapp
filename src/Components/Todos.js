import React from "react";
import Todo from "./Todo";

const Todos = (props) => {
  let myStyle = {
    minHeight: "100vh"
  }
  return (
    <div className="container my-3" style={myStyle}>
      <h3 className="my-3">TODOS LIST</h3>

      {props.todos.length === 0
        ? "No Todos to display"
        : props.todos.map((x) => (
            <Todo todo={x} key={x.sno} onDelete={props.onDelete} />
          ))}
    </div>
  );
};

export default Todos;
