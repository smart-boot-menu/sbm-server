use crate::clock::Clock;
use crate::config::Config;
use crate::db::Db;
use crate::hub::Hub;
use crate::identity::Material;
use crate::rate::Limiter;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration, Webauthn};

pub enum Challenge {
    Register {
        state: PasskeyRegistration,
        username: String,
        display_name: String,
        user_id: String,
        existing_operator: Option<String>,
        expires_at: i64,
    },
    Login {
        state: PasskeyAuthentication,
        operator_id: String,
        expires_at: i64,
    },
}

#[derive(Clone, Default)]
pub struct ChallengeStore {
    inner: Arc<Mutex<HashMap<String, Challenge>>>,
}

impl ChallengeStore {
    pub fn insert(&self, id: String, challenge: Challenge) {
        let mut guard = self.inner.lock().expect("challenge store");
        let now = match &challenge {
            Challenge::Register { expires_at, .. } | Challenge::Login { expires_at, .. } => {
                *expires_at
            }
        };
        guard.retain(|_, item| match item {
            Challenge::Register { expires_at, .. } | Challenge::Login { expires_at, .. } => {
                *expires_at > now - 300
            }
        });
        guard.insert(id, challenge);
    }

    pub fn take(&self, id: &str) -> Option<Challenge> {
        self.inner.lock().expect("challenge store").remove(id)
    }
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: Db,
    pub identity: Arc<RwLock<Material>>,
    pub clock: Clock,
    pub webauthn: Arc<Webauthn>,
    pub challenges: ChallengeStore,
    pub limiter: Limiter,
    pub hub: Hub,
}
