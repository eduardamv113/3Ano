const todos = [
  'Learn a new course',
  'Read a book',
  'Go to the gym',
  'Go shopping'
];

/* Ex. 1: Add a event listener that triggers when the DOM is loaded here */
document.addEventListener('DOMContentLoaded', () => {
  const dateElement = document.getElementById('list-date');
  const today = new Date().toLocaleDateString('pt-PT'); //dia de hoje
  dateElement.textContent = today;
  renderTodoList();
});


/* Ex. 2: Complete todo rendering */
// complete function to remove all child nodes
// arg parent is the node to clean
function removeAllChildNodes(parent) {
  
}


// render todo array here
function renderTodoList() {

  const todoListElement = document.getElementById('todo-list');

  todos.forEach(todo => {
    const todoItem = document.createElement('li');
    const todoText = document.createElement('p');
    const todoButton = document.createElement('button');

    todoText.textContent = todo;
    todoButton.textContent = 'Delete';

    todoItem.classList.add('todo-list-item');
    todoItem.appendChild(todoText);

    todoItem.appendChild(todoButton);

    todoListElement.appendChild(todoItem);

})
  
}



/* Ex. 3: Add a event listener to element 'todo-form'*/
document.getElementById('todo-form').addEventListener('submit', event => {
  event.preventDefault();//nao faz refresh da pagina
  const taskInput = document.getElementById('task-input');
  const todoValue = taskInput.value;
  taskInput.value = '';//limpar o input

  if(todoValue === '') return;

  //se tentarmos adicionar um todo vazio, nada acontece
  //dar trigger a alerta 
  if(todos.includes(todoValue)) {
    alert('Erro! ' + todoValue +  ' já existe.');
    return;
  }
  todos.push(todoValue);
  renderTodoList();  
});




/* Ex. 4 and 5: complete delete button click logic */
// arg event is the triggered event (with event you can get the element clicked).
function removeTodoItem(event) {
  
}