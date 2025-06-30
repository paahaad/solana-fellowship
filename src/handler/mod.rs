use axum::{extract::{Path, State}, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    native_token::LAMPORTS_PER_SOL, 
    pubkey::Pubkey, 
    signature::{Keypair, Signature}, 
    signer::Signer,
    system_instruction,
};
use spl_token::instruction;
use std::str::FromStr;
use base64::{Engine as _, engine::general_purpose};

use crate::router::AppState;

#[derive(Serialize)]
pub struct StandardResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T> StandardResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }
    
    pub fn error(error: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
        }
    }
}

#[derive(Serialize)]
pub struct BalanceResponse {
    pub lamports: u64,
    pub sol: f64,
}

#[derive(Deserialize)]
pub struct AirdropRequest {
    pub address: String,
    pub sol: f64,
}

#[derive(Serialize)]
pub struct AirdropResponse {
    pub signature: String,
}

#[derive(Serialize)]
pub struct KeypairData {
    pub pubkey: String,
    pub secret: String,
}

#[derive(Deserialize)]
pub struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    pub mint_authority: String,
    pub mint: String,
    pub decimals: u8,
}

#[derive(Serialize)]
pub struct InstructionAccount {
    pub pubkey: String,
    pub is_signer: bool,
    pub is_writable: bool,
}

#[derive(Serialize)]
pub struct InstructionData {
    pub program_id: String,
    pub accounts: Vec<InstructionAccount>,
    pub instruction_data: String,
}

#[derive(Deserialize)]
pub struct MintTokenRequest {
    pub mint: String,
    pub destination: String,
    pub authority: String,
    pub amount: u64,
}

#[derive(Deserialize)]
pub struct SignMessageRequest {
    pub message: String,
    pub secret: String,
}

#[derive(Serialize)]
pub struct SignMessageData {
    pub signature: String,
    pub public_key: String,
    pub message: String,
}

#[derive(Deserialize)]
pub struct VerifyMessageRequest {
    pub message: String,
    pub signature: String,
    pub pubkey: String,
}

#[derive(Serialize)]
pub struct VerifyMessageData {
    pub valid: bool,
    pub message: String,
    pub pubkey: String,
}

#[derive(Deserialize)]
pub struct SendSolRequest {
    pub from: String,
    pub to: String,
    pub lamports: u64,
}

#[derive(Deserialize)]
pub struct SendTokenRequest {
    pub destination: String,
    pub mint: String,
    pub owner: String,
    pub amount: u64,
}

#[derive(Serialize)]
pub struct TransferInstructionData {
    pub program_id: String,
    pub accounts: Vec<InstructionAccount>,
    pub instruction_data: String,
}

pub async fn generate_keypair() -> Result<Json<StandardResponse<KeypairData>>, (StatusCode, Json<StandardResponse<()>>)> {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(&keypair.to_bytes()).into_string();
    
    let data = KeypairData { pubkey, secret };
    Ok(Json(StandardResponse::success(data)))
}

pub async fn create_token(
    Json(payload): Json<CreateTokenRequest>,
) -> Result<Json<StandardResponse<InstructionData>>, (StatusCode, Json<StandardResponse<()>>)> {
    let mint_authority = match Pubkey::from_str(&payload.mint_authority) {
        Ok(key) => key,
        Err(e) => return Err((StatusCode::BAD_REQUEST, Json(StandardResponse::error(format!("Invalid mint authority public key: {e}"))))),
    };

    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(key) => key,
        Err(e) => return Err((StatusCode::BAD_REQUEST, Json(StandardResponse::error(format!("Invalid mint public key: {e}"))))),
    };

    let instruction = match instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        Some(&mint_authority),
        payload.decimals,
    ) {
        Ok(instr) => instr,
        Err(e) => return Err((StatusCode::BAD_REQUEST, Json(StandardResponse::error(format!("Failed to create initialize mint instruction: {e}"))))),
    };

    let accounts: Vec<InstructionAccount> = instruction
        .accounts
        .iter()
        .map(|account| InstructionAccount {
            pubkey: account.pubkey.to_string(),
            is_signer: account.is_signer,
            is_writable: account.is_writable,
        })
        .collect();

    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);

    let data = InstructionData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    };

    Ok(Json(StandardResponse::success(data)))
}

pub async fn mint_token(
    Json(payload): Json<MintTokenRequest>,
) -> Result<Json<StandardResponse<InstructionData>>, (StatusCode, Json<StandardResponse<()>>)> {
    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(key) => key,
        Err(e) => return Err((StatusCode::BAD_REQUEST, Json(StandardResponse::error(format!("Invalid mint public key: {e}"))))),
    };

    let destination = match Pubkey::from_str(&payload.destination) {
        Ok(key) => key,
        Err(e) => return Err((StatusCode::BAD_REQUEST, Json(StandardResponse::error(format!("Invalid destination public key: {e}"))))),
    };

    let authority = match Pubkey::from_str(&payload.authority) {
        Ok(key) => key,
        Err(e) => return Err((StatusCode::BAD_REQUEST, Json(StandardResponse::error(format!("Invalid authority public key: {e}"))))),
    };

    let instruction = match instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        payload.amount,
    ) {
        Ok(instr) => instr,
        Err(e) => return Err((StatusCode::BAD_REQUEST, Json(StandardResponse::error(format!("Failed to create mint to instruction: {e}"))))),
    };

    let accounts: Vec<InstructionAccount> = instruction
        .accounts
        .iter()
        .map(|account| InstructionAccount {
            pubkey: account.pubkey.to_string(),
            is_signer: account.is_signer,
            is_writable: account.is_writable,
        })
        .collect();

    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);

    let data = InstructionData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    };

    Ok(Json(StandardResponse::success(data)))
}

pub async fn get_balance(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<BalanceResponse>, (StatusCode, String)> {
    let pubkey = Pubkey::from_str(&address).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid public key '{address}': {e}"),
        )
    })?;

    match state.rpc_client.get_balance(&pubkey) {
        Ok(lamports) => {
            let sol = lamports as f64 / LAMPORTS_PER_SOL as f64;
            Ok(Json(BalanceResponse { lamports, sol }))
        }
        Err(err) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("RPC error: {err}"),
        )),
    }
}

pub async fn request_airdrop(
    State(state): State<AppState>,
    Json(payload): Json<AirdropRequest>,
) -> Result<Json<AirdropResponse>, (StatusCode, String)> {
    let pubkey = Pubkey::from_str(&payload.address).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid public key '{}': {e}", payload.address),
        )
    })?;

    let lamports = (payload.sol * LAMPORTS_PER_SOL as f64) as u64;

    match state.rpc_client.request_airdrop(&pubkey, lamports) {
        Ok(sig) => Ok(Json(AirdropResponse {
            signature: sig.to_string(),
        })),
        Err(err) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Airdrop failed: {err}"),
        )),
    }
}

pub async fn sign_message(
    Json(payload): Json<SignMessageRequest>,
) -> Result<Json<StandardResponse<SignMessageData>>, (StatusCode, Json<StandardResponse<()>>)> {
    let secret_bytes = match bs58::decode(&payload.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(e) => return Err((StatusCode::BAD_REQUEST, Json(StandardResponse::error(format!("Invalid secret key format: {e}"))))),
    };

    if secret_bytes.len() != 64 {
        return Err((StatusCode::BAD_REQUEST, Json(StandardResponse::error("Invalid secret key length".to_string()))));
    }

    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(e) => return Err((StatusCode::BAD_REQUEST, Json(StandardResponse::error(format!("Invalid keypair: {e}"))))),
    };

    let message_bytes = payload.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);
    
    let data = SignMessageData {
        signature: general_purpose::STANDARD.encode(signature.as_ref()),
        public_key: keypair.pubkey().to_string(),
        message: payload.message,
    };

    Ok(Json(StandardResponse::success(data)))
}

pub async fn verify_message(
    Json(payload): Json<VerifyMessageRequest>,
) -> Result<Json<StandardResponse<VerifyMessageData>>, (StatusCode, Json<StandardResponse<()>>)> {
    // Parse the public key
    let pubkey = match Pubkey::from_str(&payload.pubkey) {
        Ok(key) => key,
        Err(e) => return Err((StatusCode::BAD_REQUEST, Json(StandardResponse::error(format!("Invalid public key: {e}"))))),
    };

    let signature_bytes = match general_purpose::STANDARD.decode(&payload.signature) {
        Ok(bytes) => bytes,
        Err(e) => return Err((StatusCode::BAD_REQUEST, Json(StandardResponse::error(format!("Invalid signature format: {e}"))))),
    };

    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(e) => return Err((StatusCode::BAD_REQUEST, Json(StandardResponse::error(format!("Invalid signature: {e}"))))),
    };

    let message_bytes = payload.message.as_bytes();
    let valid = signature.verify(&pubkey.to_bytes(), message_bytes);

    let data = VerifyMessageData {
        valid,
        message: payload.message,
        pubkey: payload.pubkey,
    };

    Ok(Json(StandardResponse::success(data)))
}

pub async fn send_sol(
    Json(payload): Json<SendSolRequest>,
) -> Result<Json<StandardResponse<TransferInstructionData>>, (StatusCode, Json<StandardResponse<()>>)> {
    let from_pubkey = match Pubkey::from_str(&payload.from) {
        Ok(key) => key,
        Err(e) => return Err((StatusCode::BAD_REQUEST, Json(StandardResponse::error(format!("Invalid from address: {e}"))))),
    };

    let to_pubkey = match Pubkey::from_str(&payload.to) {
        Ok(key) => key,
        Err(e) => return Err((StatusCode::BAD_REQUEST, Json(StandardResponse::error(format!("Invalid to address: {e}"))))),
    };

    if payload.lamports == 0 {
        return Err((StatusCode::BAD_REQUEST, Json(StandardResponse::error("Amount must be greater than 0".to_string()))));
    }

    let instruction = system_instruction::transfer(&from_pubkey, &to_pubkey, payload.lamports);

    let accounts: Vec<InstructionAccount> = instruction
        .accounts
        .iter()
        .map(|account| InstructionAccount {
            pubkey: account.pubkey.to_string(),
            is_signer: account.is_signer,
            is_writable: account.is_writable,
        })
        .collect();

    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);

    let data = TransferInstructionData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    };

    Ok(Json(StandardResponse::success(data)))
}

pub async fn send_token(
    Json(payload): Json<SendTokenRequest>,
) -> Result<Json<StandardResponse<TransferInstructionData>>, (StatusCode, Json<StandardResponse<()>>)> {
    let destination = match Pubkey::from_str(&payload.destination) {
        Ok(key) => key,
        Err(e) => return Err((StatusCode::BAD_REQUEST, Json(StandardResponse::error(format!("Invalid destination address: {e}"))))),
    };

    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(key) => key,
        Err(e) => return Err((StatusCode::BAD_REQUEST, Json(StandardResponse::error(format!("Invalid mint address: {e}"))))),
    };

    let owner = match Pubkey::from_str(&payload.owner) {
        Ok(key) => key,
        Err(e) => return Err((StatusCode::BAD_REQUEST, Json(StandardResponse::error(format!("Invalid owner address: {e}"))))),
    };

    if payload.amount == 0 {
        return Err((StatusCode::BAD_REQUEST, Json(StandardResponse::error("Amount must be greater than 0".to_string()))));
    }

    let source = spl_associated_token_account::get_associated_token_address(&owner, &mint);

    let instruction = match instruction::transfer(
        &spl_token::id(),
        &source,
        &destination,
        &owner,
        &[],
        payload.amount,
    ) {
        Ok(instr) => instr,
        Err(e) => return Err((StatusCode::BAD_REQUEST, Json(StandardResponse::error(format!("Failed to create transfer instruction: {e}"))))),
    };

    let accounts: Vec<InstructionAccount> = instruction
        .accounts
        .iter()
        .map(|account| InstructionAccount {
            pubkey: account.pubkey.to_string(),
            is_signer: account.is_signer,
            is_writable: account.is_writable,
        })
        .collect();

    let instruction_data = general_purpose::STANDARD.encode(&instruction.data);

    let data = TransferInstructionData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    };

    Ok(Json(StandardResponse::success(data)))
}
