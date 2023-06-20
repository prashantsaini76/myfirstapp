import React from 'react'

const Todo = (props) => {
  return (
    <div>
      <h4>{props.todo.title}</h4>
      <p>{props.todo.desc}</p>
      <button className="btn btn-sm btn-danger" onClick={()=>props.onDelete(props.todo)}>Delete</button> 
      <hr/>
    </div>
  )
}

export default Todo
