import { createRouter, createWebHistory } from 'vue-router';
import GamePage from './pages/GamePage.vue';
import SimulationPage from './pages/SimulationPage.vue';
import StatisticsPage from './pages/StatisticsPage.vue';
import NotFoundPage from './pages/NotFoundPage.vue';

const router = createRouter({
history: createWebHistory(),
routes: [
  {path: '/', redirect: '/game '},
  {path: '/game', component: GamePage},
  {path: '/simulation', component: SimulationPage},
  {path: '/statistics', component: StatisticsPage},
  {path: '/not-found', component: NotFoundPage},
  {path: '/game/:id', component: GamePage, props: true},
]
});

export default router;