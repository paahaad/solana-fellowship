use std::{net::SocketAddr, sync::Arc};

use solana_client::rpc_client::RpcClient;
use tokio::net::TcpListener;

mod router;
mod handler;

#[tokio::main]
async fn main() {
    
    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());

    let rpc_client = Arc::new(RpcClient::new(rpc_url));

    let state = router::AppState { rpc_client };
    let app = router::create_router(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    let listener = TcpListener::bind(addr).await.expect("bind listener");
    println!("🚀 Axum server listening on http://{addr}");
    axum::serve(listener, app.into_make_service())
        .await
        .expect("server failed");
}

