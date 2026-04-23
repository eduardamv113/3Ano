import './assets/main.css';
import { createApp } from 'vue';
import router from './router';
import App from './App.vue';
import GameBoard from './components/GameBoard.vue';
import ButtonComponent from './components/ui/ButtonComponent.vue';
import { createPinia } from 'pinia';

const app = createApp(App);

app.component('ButtonComponent', ButtonComponent);
app.component('GameBoard', GameBoard);
app.use(router);
app.use(createPinia());
app.mount('#app');
// TODO: usar PrimeVue e usar um preset
app.use(PrimeVue, { 
    });
// TODO: registar o ToastService no app
app.use(ToastService);