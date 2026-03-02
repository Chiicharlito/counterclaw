//! Adaptive Poller — machine à états pour le polling intelligent.
//!
//! Réduit la consommation CPU quand aucun processus surveillé n'est actif.
//! Trois états :
//! - **Idle** : pas de processus surveillé → polling lent (30s)
//! - **Active** : processus surveillé détecté → polling rapide (configurable)
//! - **Backoff** : processus disparu → transition douce vers Idle

use std::time::Duration;

/// État de la machine à états du poller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollerState {
    /// Aucun processus surveillé actif — polling lent.
    Idle,
    /// Processus surveillé détecté — polling rapide.
    Active,
    /// Processus disparu — transition vers Idle avec compteur.
    Backoff,
}

/// Machine à états pour adapter la fréquence de polling
/// selon la présence de processus surveillés.
pub struct AdaptivePoller {
    state: PollerState,
    idle_interval: Duration,
    active_interval: Duration,
    backoff_interval: Duration,
    backoff_max_ticks: u32,
    backoff_remaining: u32,
}

impl AdaptivePoller {
    /// Crée un nouveau poller avec l'intervalle actif spécifié.
    /// Utilise les valeurs par défaut : idle=30s, backoff=5s, 3 ticks backoff.
    pub fn new(active_interval: Duration) -> Self {
        Self {
            state: PollerState::Idle,
            idle_interval: Duration::from_secs(30),
            active_interval,
            backoff_interval: Duration::from_secs(5),
            backoff_max_ticks: 3,
            backoff_remaining: 0,
        }
    }

    /// Crée un nouveau poller avec tous les intervalles personnalisés.
    pub fn with_intervals(
        idle_interval: Duration,
        active_interval: Duration,
        backoff_interval: Duration,
        backoff_ticks: u32,
    ) -> Self {
        Self {
            state: PollerState::Idle,
            idle_interval,
            active_interval,
            backoff_interval,
            backoff_max_ticks: backoff_ticks,
            backoff_remaining: 0,
        }
    }

    /// Retourne l'intervalle de sleep correspondant à l'état courant.
    pub fn current_interval(&self) -> Duration {
        match self.state {
            PollerState::Idle => self.idle_interval,
            PollerState::Active => self.active_interval,
            PollerState::Backoff => self.backoff_interval,
        }
    }

    /// Effectue une transition d'état basée sur la présence de processus surveillés.
    pub fn transition(&mut self, watched_found: bool) {
        match self.state {
            PollerState::Idle => {
                if watched_found {
                    self.state = PollerState::Active;
                }
                // Idle + not found → stay Idle
            }
            PollerState::Active => {
                if !watched_found {
                    self.state = PollerState::Backoff;
                    self.backoff_remaining = self.backoff_max_ticks;
                }
                // Active + found → stay Active
            }
            PollerState::Backoff => {
                if watched_found {
                    self.state = PollerState::Active;
                    self.backoff_remaining = 0;
                } else {
                    self.backoff_remaining = self.backoff_remaining.saturating_sub(1);
                    if self.backoff_remaining == 0 {
                        self.state = PollerState::Idle;
                    }
                }
            }
        }
    }

    /// Retourne l'état courant.
    pub fn state(&self) -> PollerState {
        self.state.clone()
    }
}
