pub mod hub;
pub mod message;
pub mod username_proof;

use candid::{candid_method, CandidType, Principal};
use ic_cdk::api::management_canister::http_request::{HttpResponse, TransformArgs};
use ic_cdk_macros::{self, update, query};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::str::FromStr;

use ic_web3::transports::ICHttp;
use ic_web3::Web3;
use ic_web3::ic::{get_eth_addr, KeyInfo};
use ic_web3::{
    contract::{Contract, Options},
    ethabi::ethereum_types::{U64, U256},
    types::{Address, TransactionParameters, BlockId},
};

use message::{CastAddBody, FarcasterNetwork, MessageData};
use protobuf::Message;
const FARCASTER_EPOCH: i64 = 1609459200; // January 1, 2021 UTC
const URL: &str = "https://rpc.ankr.com/optimism/dc7b9c29c873ec7052717f3edd95907ec711d61fdb948b307a609411ea828cc2";
//const URL: &str = "https://ethereum.publicnode.com";
//const URL: &str = "https://eth-goerli.g.alchemy.com/v2/0QCHDmgIEFRV48r1U1QbtOyFInib3ZAm";
const CHAIN_ID: u64 = 10;
//const CHAIN_ID: u64 = 1;
//const KEY_NAME: &str = "dfx_test_key";
const KEY_NAME: &str = "test_key_1";
const ID_GATEWAY_ABI: &[u8] = include_bytes!("../abi/idGateway.json");
const STORAGE_REGISTRY_ABI: &[u8] = include_bytes!("../abi/storageRegistry.json");

type Result<T, E> = std::result::Result<T, E>;

/*#[query(name = "transform")]
#[candid_method(query, rename = "transform")]
fn transform(response: TransformArgs) -> HttpResponse {
    let mut t = response.response;
    t.headers = vec![];
    t 
}*/

#[update(name = "get_block")]
#[candid_method(update, rename = "get_block")]
async fn get_block(number: u64) -> Result<String, String> {
  
    let w3 = match ICHttp::new(URL, None) {
        Ok(v) => { Web3::new(v) },
        Err(e) => { return Err(e.to_string()) },
    };
    let block_id = BlockId::from(U64::from(number));
    let block = w3.eth().block(block_id).await.map_err(|e| format!("get block error: {}", e))?;
    ic_cdk::println!("block: {:?}", block.clone().unwrap());

    Ok(serde_json::to_string(&block.unwrap()).unwrap())
}

#[update(name = "get_eth_gas_price")]
#[candid_method(update, rename = "get_eth_gas_price")]
async fn get_eth_gas_price() -> Result<String, String> {
    let w3 = match ICHttp::new(URL, None) {
        Ok(v) => { Web3::new(v) },
        Err(e) => { return Err(e.to_string()) },
    };
    let gas_price = w3.eth().gas_price().await.map_err(|e| format!("get gas price failed: {}", e))?;
    //let gas_price = U256::from(10000000);
    ic_cdk::println!("gas price: {}", gas_price);
    Ok(format!("{}", gas_price))
}

// get canister's ethereum address
#[update(name = "get_canister_addr")]
#[candid_method(update, rename = "get_canister_addr")]
async fn get_canister_addr() -> Result<String, String> {
    match get_eth_addr(None, None, KEY_NAME.to_string()).await {
        Ok(addr) => { Ok(hex::encode(addr)) },
        Err(e) => { Err(e) },
    }
}

#[update(name = "get_tx_count")]
#[candid_method(update, rename = "get_tx_count")]
async fn get_tx_count(addr: String) -> Result<u64, String> {
    let w3 = match ICHttp::new(URL, None) {
        Ok(v) => { Web3::new(v) },
        Err(e) => { return Err(e.to_string()) },
    };
    let from_addr = Address::from_str(&addr).unwrap();
    let tx_count = w3.eth()
        .transaction_count(from_addr, None)
        .await
        .map_err(|e| format!("get tx count error: {}", e))?;
    Ok(tx_count.as_u64())
}
 

#[update(name = "get_eth_balance")]
#[candid_method(update, rename = "get_eth_balance")]
async fn get_eth_balance(addr: String) -> Result<String, String> {
    let w3 = match ICHttp::new(URL, None) {
        Ok(v) => { Web3::new(v) },
        Err(e) => { return Err(e.to_string()) },
    };
    let balance = w3.eth().balance(Address::from_str(&addr).unwrap(), None).await.map_err(|e| format!("get balance failed: {}", e))?;
    Ok(format!("{}", balance))
}

#[update(name = "batch_request")]
#[candid_method(update, rename = "batch_request")]
async fn batch_request() -> Result<String, String> {
    let http = ICHttp::new(URL, None).map_err(|e| format!("init ICHttp failed: {}", e))?;
    let w3 = Web3::new(ic_web3::transports::Batch::new(http));

    let block_number = w3.eth().block_number();
    let gas_price = w3.eth().gas_price();
    let balance = w3.eth().balance(Address::from([0u8; 20]), None);

    let result = w3.transport().submit_batch().await.map_err(|e| format!("batch request err: {}", e))?;
    ic_cdk::println!("batch request result: {:?}", result);

    let block_number = block_number.await.map_err(|e| format!("get block number err: {}", e))?;
    ic_cdk::println!("block number: {:?}", block_number);

    let gas_price = gas_price.await.map_err(|e| format!("get gas price err: {}", e))?;
    ic_cdk::println!("gas price: {:?}", gas_price);

    let balance = balance.await.map_err(|e| format!("get balance err: {}", e))?;
    ic_cdk::println!("balance: {:?}", balance);

    Ok("done".into())
}

// send tx to eth
#[update(name = "send_eth")]
#[candid_method(update, rename = "send_eth")]
async fn send_eth(to: String, value: u64, nonce: Option<u64>) -> Result<String, String> {
    // ecdsa key info
    let derivation_path = vec![ic_cdk::id().as_slice().to_vec()];
    let key_info = KeyInfo{ derivation_path: derivation_path, key_name: KEY_NAME.to_string(), ecdsa_sign_cycles: None };

    // get canister eth address
    let from_addr = get_eth_addr(None, None, KEY_NAME.to_string())
        .await
        .map_err(|e| format!("get canister eth addr failed: {}", e))?;
    // get canister the address tx count
    let w3 = match ICHttp::new(URL, None) {
        Ok(v) => { Web3::new(v) },
        Err(e) => { return Err(e.to_string()) },
    };
    let tx_count: U256 = if let Some(count) = nonce {
        count.into() 
    } else {
        let v = w3.eth()
            .transaction_count(from_addr, None)
            .await
            .map_err(|e| format!("get tx count error: {}", e))?;
        v
    };
        
    ic_cdk::println!("canister eth address {} tx count: {}", hex::encode(from_addr), tx_count);
    // construct a transaction
    let to = Address::from_str(&to).unwrap();
    let tx = TransactionParameters {
        to: Some(to),
        nonce: Some(tx_count), // remember to fetch nonce first
        value: U256::from(value),
        gas_price: Some(U256::from(100_000_000_000u64)), // 100 gwei
        gas: U256::from(21000),
        ..Default::default()
    };
    // sign the transaction and get serialized transaction + signature
    let signed_tx = w3.accounts()
        .sign_transaction(tx, hex::encode(from_addr), key_info, CHAIN_ID)
        .await
        .map_err(|e| format!("sign tx error: {}", e))?;
    match w3.eth().send_raw_transaction(signed_tx.raw_transaction).await {
        Ok(txhash) => { 
            ic_cdk::println!("txhash: {}", hex::encode(txhash.0));
            Ok(format!("{}", hex::encode(txhash.0)))
        },
        Err(_e) => { Ok(hex::encode(signed_tx.message_hash)) },
    }
}

// query a contract, token balance
#[update(name = "token_balance")]
#[candid_method(update, rename = "token_balance")]
async fn token_balance(contract_addr: String, addr: String) -> Result<String, String> {
    // goerli weth: 0xb4fbf271143f4fbf7b91a5ded31805e42b2208d6
    // account: 0x9c9fcF808B82e5fb476ef8b7A1F5Ad61Dc597625
    let w3 = match ICHttp::new(URL, None) {
        Ok(v) => { Web3::new(v) },
        Err(e) => { return Err(e.to_string()) },
    };
    let contract_address = Address::from_str(&contract_addr).unwrap();
    let contract = Contract::from_json(
        w3.eth(),
        contract_address,
        ID_GATEWAY_ABI
    ).map_err(|e| format!("init contract failed: {}", e))?;

    let addr = Address::from_str(&addr).unwrap();
    let balance: U256 = contract
        .query("balanceOf", (addr,), None, Options::default(), None)
        .await
        .map_err(|e| format!("query contract error: {}", e))?;
    ic_cdk::println!("balance of {} is {}", addr, balance);
    Ok(format!("{}", balance))
}

// call a contract, transfer some token to addr
#[update(name = "rpc_call")]
#[candid_method(update, rename = "rpc_call")]
async fn rpc_call(body: String) -> Result<String, String> {

    let w3 = match ICHttp::new(URL, None) {
        Ok(v) => { Web3::new(v) },
        Err(e) => { return Err(e.to_string()) },
    };

    let res = w3.json_rpc_call(body.as_ref()).await.map_err(|e| format!("{}", e))?;

    ic_cdk::println!("result: {}", res);

    Ok(format!("{}", res))
}

#[cfg(not(any(target_arch = "wasm32", test)))]
fn main() {
    candid::export_service!();
    std::print!("{}", __export_service());
}

#[cfg(any(target_arch = "wasm32", test))]
fn main() {}

// call a contract, transfer some token to addr
#[update(name = "create_account")]
#[candid_method(update, rename = "create_account")]
async fn create_account() -> Result<String, String> {

    let contract_addr = "0x00000000Fc25870C6eD6b6c7E41Fb078b7656f69";
    let recovery = "0x9dA843bc087465f70c6317eA5E0EB47F20C5b0bc";
    let nonce = U256::from(22);
    // ecdsa key info
    let derivation_path = vec![ic_cdk::id().as_slice().to_vec()];
    let key_info = KeyInfo{ derivation_path: derivation_path, key_name: KEY_NAME.to_string(), ecdsa_sign_cycles: None };

    // get canister eth address
    let from_addr = get_eth_addr(None, None, KEY_NAME.to_string())
        .await
        .map_err(|e| format!("get canister eth addr failed: {}", e))?;
    let w3 = match ICHttp::new(URL, None) {
        Ok(v) => { Web3::new(v) },
        Err(e) => { return Err(e.to_string()) },
    };
    let contract_address = Address::from_str(&contract_addr).unwrap();
    let contract = Contract::from_json(
        w3.eth(),
        contract_address,
        ID_GATEWAY_ABI
    ).map_err(|e| format!("init contract failed: {}", e))?;

    let canister_addr = get_eth_addr(None, None, KEY_NAME.to_string())
        .await
        .map_err(|e| format!("get canister eth addr failed: {}", e))?;
    // add nonce to options
    /*let tx_count: U256 = if let Some(count) = nonce {
        count.into() 
    } else {
        let v = w3.eth()
            .transaction_count(from_addr, None)
            .await
            .map_err(|e| format!("get tx count error: {}", e))?;
        v
    };*/
     
    // get gas_price
    /*let gas_price = w3.eth()
        .gas_price()
        .await
        .map_err(|e| format!("get gas_price error: {}", e))?;*/
    let gas_price = U256::from(1023001050);
    let gas = U256::from(100000);
    let value = U256::from("9000010500000");
    
    // legacy transaction type is still ok
    let options = Options::with(|op| { 
        op.nonce = Some(nonce);
        op.gas_price = Some(gas_price);
        op.gas = Some(gas);
        op.value = Some(value);
        //op.transaction_type = Some(U64::from(1)) //EIP1559_TX_ID
    });
    let recovery_addr = Address::from_str(&recovery).unwrap();
    let txhash = contract
        .signed_call("register", recovery_addr, options, hex::encode(canister_addr), key_info, CHAIN_ID)
        .await
        .map_err(|e| format!("Contract Call: {}", e))?;

    ic_cdk::println!("txhash: {}", hex::encode(txhash));

    Ok(format!("{}", hex::encode(txhash)))
}

#[update(name = "rent")]
#[candid_method(update, rename = "rent")]
async fn rent() -> Result<String, String> {

    let contract_addr = "0x00000000fcce7f938e7ae6d3c335bd6a1a7c593d";
    let fid = U256::from(345878);
    let units = U256::from(1);
    let nonce = U256::from(24);
    // ecdsa key info
    let derivation_path = vec![ic_cdk::id().as_slice().to_vec()];
    let key_info = KeyInfo{ derivation_path: derivation_path, key_name: KEY_NAME.to_string(), ecdsa_sign_cycles: None };

    // get canister eth address
    let from_addr = get_eth_addr(None, None, KEY_NAME.to_string())
        .await
        .map_err(|e| format!("get canister eth addr failed: {}", e))?;
    let w3 = match ICHttp::new(URL, None) {
        Ok(v) => { Web3::new(v) },
        Err(e) => { return Err(e.to_string()) },
    };
    let contract_address = Address::from_str(&contract_addr).unwrap();
    let contract = Contract::from_json(
        w3.eth(),
        contract_address,
        STORAGE_REGISTRY_ABI
    ).map_err(|e| format!("init contract failed: {}", e))?;

    let canister_addr = get_eth_addr(None, None, KEY_NAME.to_string())
        .await
        .map_err(|e| format!("get canister eth addr failed: {}", e))?;
    // add nonce to options
    /*let tx_count: U256 = if let Some(count) = nonce {
        count.into() 
    } else {
        let v = w3.eth()
            .transaction_count(from_addr, None)
            .await
            .map_err(|e| format!("get tx count error: {}", e))?;
        v
    };*/
     
    // get gas_price
    /*let gas_price = w3.eth()
        .gas_price()
        .await
        .map_err(|e| format!("get gas_price error: {}", e))?;*/
    let gas_price = U256::from(1023001050);
    let gas = U256::from(100000);
    let value = U256::from("9000010500000");
    
    // legacy transaction type is still ok
    let options = Options::with(|op| { 
        op.nonce = Some(nonce);
        op.gas_price = Some(gas_price);
        op.gas = Some(gas);
        op.value = Some(value);
        //op.transaction_type = Some(U64::from(1)) //EIP1559_TX_ID
    });
    let txhash = contract
        .signed_call("rent", (fid, units), options, hex::encode(canister_addr), key_info, CHAIN_ID)
        .await
        .map_err(|e| format!("Contract Call: {}", e))?;

    ic_cdk::println!("txhash: {}", hex::encode(txhash));

    Ok(format!("{}", hex::encode(txhash)))
}


#[update(name = "cast")]
#[candid_method(update, rename = "cast")]
async fn cast() -> String {
    let fid:u64 = 345878;
    let timestamp = ic_cdk::api::time();
    let network = FarcasterNetwork::FARCASTER_NETWORK_MAINNET;

    // Construct the cast add message
    let mut cast_add = CastAddBody::new();
    cast_add.set_text("Hello World! from the Internet Computer :)".to_string());
    let epoch = std::time::SystemTime::UNIX_EPOCH;
    // Construct the cast add message data object
    let mut msg_data = MessageData::new();
    msg_data.set_field_type(message::MessageType::MESSAGE_TYPE_CAST_ADD);
    msg_data.set_fid(fid);
    msg_data.set_timestamp(
        (std::time::SystemTime::now()
            .duration_since(epoch)
            .unwrap()
            .as_secs()) as u32,
    );
    msg_data.set_network(network);
    msg_data.set_cast_add_body(cast_add);

    let msg_data_bytes = msg_data.write_to_bytes().unwrap();

    // Calculate the blake3 hash, trucated to 20 bytes
    let hash = blake3::hash(&msg_data_bytes).as_bytes()[0..20].to_vec();

    // Construct the actual message
    let mut msg = message::Message::new();
    msg.set_hash_scheme(message::HashScheme::HASH_SCHEME_BLAKE3);
    msg.set_hash(hash);

    // Sign the message. You need to use a signing key that corresponds to the FID you are adding.
    let signature = (sign(msg_data_bytes.clone()).await).unwrap();

    msg.set_signature_scheme(message::SignatureScheme::SIGNATURE_SCHEME_EIP712);
    msg.set_signature(signature.to_vec());
    //msg.set_signer(private_key.verifying_key().to_bytes().to_vec());

    // Serialize the message
    msg.set_data_bytes(msg_data_bytes.to_vec());
    let msg_bytes = msg.write_to_bytes().unwrap();
    hub::submit_message(msg_bytes).await
}

#[derive(CandidType, Serialize, Debug)]
struct PublicKeyReply {
    pub public_key_hex: String,
}

#[derive(CandidType, Serialize, Debug)]
struct SignatureReply {
    pub signature_hex: String,
}

#[derive(CandidType, Serialize, Debug)]
struct SignatureVerificationReply {
    pub is_signature_valid: bool,
}

type CanisterId = Principal;

#[derive(CandidType, Serialize, Debug)]
struct ECDSAPublicKey {
    pub canister_id: Option<CanisterId>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: EcdsaKeyId,
}

#[derive(CandidType, Deserialize, Debug)]
struct ECDSAPublicKeyReply {
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
}

#[derive(CandidType, Serialize, Debug)]
struct SignWithECDSA {
    pub message_hash: Vec<u8>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: EcdsaKeyId,
}

#[derive(CandidType, Deserialize, Debug)]
struct SignWithECDSAReply {
    pub signature: Vec<u8>,
}

#[derive(CandidType, Serialize, Debug, Clone)]
struct EcdsaKeyId {
    pub curve: EcdsaCurve,
    pub name: String,
}

#[derive(CandidType, Serialize, Debug, Clone)]
pub enum EcdsaCurve {
    #[serde(rename = "secp256k1")]
    Secp256k1,
}

async fn public_key() -> Result<PublicKeyReply, String> {
    let request = ECDSAPublicKey {
        canister_id: None,
        derivation_path: vec![],
        key_id: EcdsaKeyIds::TestKeyLocalDevelopment.to_key_id(),
    };

    let (res,): (ECDSAPublicKeyReply,) =
        ic_cdk::call(mgmt_canister_id(), "ecdsa_public_key", (request,))
            .await
            .map_err(|e| format!("ecdsa_public_key failed {}", e.1))?;

    Ok(PublicKeyReply {
        public_key_hex: hex::encode(&res.public_key),
    })
}

async fn sign(message: Vec<u8>) -> Result<Vec<u8>, String> {
    let request = SignWithECDSA {
        message_hash: message,
        derivation_path: vec![],
        key_id: EcdsaKeyIds::TestKeyLocalDevelopment.to_key_id(),
    };

    let (response,): (SignWithECDSAReply,) = ic_cdk::api::call::call_with_payment(
        mgmt_canister_id(),
        "sign_with_ecdsa",
        (request,),
        25_000_000_000,
    )
    .await
    .map_err(|e| format!("sign_with_ecdsa failed {}", e.1))?;

    Ok(response.signature)
}

fn mgmt_canister_id() -> CanisterId {
    CanisterId::from_str(&"aaaaa-aa").unwrap()
}

fn sha256(input: &String) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(input.as_bytes());
    hasher.finalize().into()
}

enum EcdsaKeyIds {
    #[allow(unused)]
    TestKeyLocalDevelopment,
    #[allow(unused)]
    TestKey1,
    #[allow(unused)]
    ProductionKey1,
}

impl EcdsaKeyIds {
    fn to_key_id(&self) -> EcdsaKeyId {
        EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: match self {
                Self::TestKeyLocalDevelopment => "dfx_test_key",
                Self::TestKey1 => "test_key_1",
                Self::ProductionKey1 => "key_1",
            }
            .to_string(),
        }
    }
}

// In the following, we register a custom getrandom implementation because
// otherwise getrandom (which is a dependency of k256) fails to compile.
// This is necessary because getrandom by default fails to compile for the
// wasm32-unknown-unknown target (which is required for deploying a canister).
// Our custom implementation always fails, which is sufficient here because
// we only use the k256 crate for verifying secp256k1 signatures, and such
// signature verification does not require any randomness.
getrandom::register_custom_getrandom!(always_fail);
pub fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}