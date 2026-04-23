import { defineStore } from "pinia";

export const useSimulationStore = defineStore('simulation', {
  state: () => {
    return {
      // TODO: declarar startPlayer
      startPlayer: null,
      plays: [], //jogadas arrazy vazio
      // TODO: declarar plays
    };
  },
  actions: {
    // TODO: implementar setStartPlayer(player)
    setStartPlayer(player) {
      this.startPlayer = player;
    },
    // TODO: implementar addPlay(play)
    addPlay(play) {
      this.plays.push(play);
    }
  },
  getters: {
    // TODO: containsSimulation -> true se startPlayer != null e plays não vazio
    containsSimulation: state => state.startPlayer !== null && state.plays.length !== 0
  }
});