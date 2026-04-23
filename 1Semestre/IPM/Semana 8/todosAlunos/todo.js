//criação da app
const app = Vue.createApp({
  data() { //função
    //armazena variaveis/estados
    return {
      todos: [
        'Learn a new course',
        'Read a book',
        'Go to the gym',
        'Go shopping'
      ],
      today: new Date().toLocaleDateString(), //exercicio 2
      enteredTodo: '' //exercicio 4, que começa vazia
    }
  },
  methods: { //objeto com varias funções dentro
   //funções usadas para manipular os dados, responder a eventos, incrementar coisas, etc.
   setEnteredTodo(event) { //exercicio 4
     this.enteredTodo = event.target.value;
   },
   //exercicio 5, função que faça submit de tudo
   submitTodo() {  
      const todo= this.enteredTodo.trim(); //pega o valor do enteredTodo, ao usar o trim serve para tirar os espaços a mais no inicio e no fim
      //evitar todos vazios
      if(todo === '') {
      alert('erro: tarefa vazia');
      return; //saimos daqui
      //nao queremos duplicados também, verificar se ja existe antes da submissao
      }
      const exists = this.todos.some(t => t.toLowerCase() === todo.toLowerCase());
      if (exists) {
        alert('erro: tarefa ja existe');
        return; //saimos daqui
      }
      this.todos.push(todo); //adicionar o todo ao array todos
      this.enteredTodo = ''; //sempre que usarmos o submit limpa o campo de input, "fica mais bonito"
   },
   deleteTodo(index) { //exercicio 6
      this.todos.splice(index, 1); //começa na posicao index e remove 1 elemento,  se pusessemos 2 removeria 2 Todos a partir do index
   }
  },
  computed: {
    //valores caluculados automaticamente com base na data
    isDisabled() { 
      return this.enteredTodo.trim() === ''; //retorna true se o enteredTodo for vazio ou só tiver espaços
    }
  }
  });
//ligar a app Vue ao elemento HTML, dixer-lhe esta aplicação vai ser posta dentro do html
app.mount('#app'); //exercicio 1