use axum::{routing::{get, post}, Router};
use solana_client::rpc_client::RpcClient;
use std::sync::Arc;

use crate::handler;

#[derive(Clone)]
pub struct AppState {
    pub(crate) rpc_client: Arc<RpcClient>,
}

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/balance/:address", get(handler::get_balance))
        .route("/airdrop", post(handler::request_airdrop))
        .route("/keypair", post(handler::generate_keypair))
        .route("/token/create", post(handler::create_token))
        .route("/token/mint", post(handler::mint_token))
        .route("/message/sign", post(handler::sign_message))
        .route("/message/verify", post(handler::verify_message))
        .route("/send/sol", post(handler::send_sol))
        .route("/send/token", post(handler::send_token))
        .with_state(state)
}
