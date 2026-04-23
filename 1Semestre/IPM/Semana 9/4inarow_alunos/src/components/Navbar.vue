<script>
import { ResultadoJogada } from '@/models/resultadoJogada';
import (ResultadoJogada)
export default {
  props: ['jogadorAJogar', 'vencedor'],
  computed: {
    texto() {
      if (this.vencedor == ResultadoJogada.VERMELHO)
        return "Vencedor: Vermelho";
      else if(this.vencedor == ResultadoJogada.AMARELO)
        return "Vencedor: Amarelo";
    }
  } 
}
</script>

<template>
  <div class="navbar">
    <h3>4 em Linha</h3>
    <div 
    class="button" 
    v-if="this.vencedor === null" 
    :class="{red: this.jogadorAJogar, yellow: !this.jogadorAJogar}">
      <p>Jogador a jogar: {{ jogadorAJogar ? 'Vermelho' : 'Amarelo' }}</p>
    </div>
    <div v-else class="button" disabled>
      <p>{{ texto }}</p>
    </div>
  </div>

</template>

<style scoped>
.button {
  border: 1px solid black;
  border-radius: 5px;
  text-align: center;
  padding: 10px;
  font-weight: 600;
}
</style>