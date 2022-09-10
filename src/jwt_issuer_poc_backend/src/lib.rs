use base58::ToBase58;
use hmac::{Hmac, Mac};
use ic_cdk::export::{
    candid::CandidType,
    serde::{Deserialize, Serialize},
    Principal,
};
use ic_cdk_macros::update;
use k256::PublicKey;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use std::{borrow::Borrow, cell::RefCell};

#[derive(Serialize, Debug)]
struct Header {
    pub alg: String,
}

#[derive(Serialize, Debug)]
struct Claims {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    pub sub: String,
}

#[derive(CandidType, Serialize, Debug)]
struct PublicKeyReply {
    pub public_key: Vec<u8>,
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

#[derive(CandidType, Debug)]
struct SignWithECDSA {
    pub message_hash: Vec<u8>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: EcdsaKeyId,
}

#[derive(CandidType, Debug, Deserialize)]
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

enum TokenKind {
    MAC,
    TECDSA,
    // ICCSA,
}

impl FromStr for TokenKind {
    type Err = ();

    fn from_str(input: &str) -> Result<TokenKind, Self::Err> {
        match input {
            "mac" => Ok(TokenKind::MAC),
            "tecdsa" => Ok(TokenKind::TECDSA),
            // "iccsa" => Ok(TokenKind::ICCSA),
            _ => Err(()),
        }
    }
}

enum PubKeyEncoding {
    RAW,
    BASE58,
    JWK,
    DID_KEY,
}

impl FromStr for PubKeyEncoding {
    type Err = ();

    fn from_str(input: &str) -> Result<PubKeyEncoding, Self::Err> {
        match input {
            "raw" => Ok(PubKeyEncoding::RAW),
            "base58" => Ok(PubKeyEncoding::BASE58),
            "jwk" => Ok(PubKeyEncoding::JWK),
            "did_key" => Ok(PubKeyEncoding::DID_KEY),
            _ => Err(()),
        }
    }
}

thread_local! {

    static MAC_KEY: Hmac<Sha256> = Hmac::new_from_slice(b"some-secret").unwrap();

    static PUB_KEY: RefCell<Vec<u8>> = RefCell::new(vec![]);
}

async fn _public_key() -> Result<PublicKeyReply, String> {
    let key_id = EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: "dfx_test_key".to_string(),
    };
    let ic_canister_id = "aaaaa-aa";
    let ic = CanisterId::from_str(&ic_canister_id).unwrap();

    // let caller = ic_cdk::caller().as_slice().to_vec();
    let request = ECDSAPublicKey {
        canister_id: None,
        derivation_path: vec![],
        key_id: key_id.clone(),
    };
    let (res,): (ECDSAPublicKeyReply,) = ic_cdk::call(ic, "ecdsa_public_key", (request,))
        .await
        .map_err(|e| format!("Failed to call ecdsa_public_key {}", e.1))?;

    println!("{}", res.public_key.len());

    Ok(PublicKeyReply {
        public_key: res.public_key,
    })
}

fn _pub_key_to_did(mut pk: Vec<u8>) -> String {
    
    const DID_KEY_SECP256K1_PREFIX: [u8; 2] = [0xe7, 0x01];
    let mut did = DID_KEY_SECP256K1_PREFIX.to_vec();

    did.append(&mut pk);

    let did = did.to_base58();
    format!("did:key:z{did}")
}

fn _sign_with_hmac(message: &str) -> Result<Vec<u8>, String> {
    let mut mac = MAC_KEY.with(|k| k.borrow().clone());

    mac.update(message.as_bytes());

    Ok(mac.finalize().into_bytes().to_vec())
}

async fn _sign_with_tecdsa(msg: &str) -> Result<Vec<u8>, String> {

    let mut hasher = Sha256::new();
    hasher.update(msg);
    let hashed = hasher.finalize();

    let message = hashed[..].to_vec();

    let key_id = EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: "dfx_test_key".to_string(),
    };
    let ic_canister_id = "aaaaa-aa";
    let ic = CanisterId::from_str(&ic_canister_id).unwrap();

    // let caller = ic_cdk::caller().as_slice().to_vec();
    let request = SignWithECDSA {
        message_hash: message.clone(),
        // derivation_path: vec![caller],
        derivation_path: vec![],
        key_id,
    };
    let (res,): (SignWithECDSAReply,) =
        ic_cdk::api::call::call_with_payment(ic, "sign_with_ecdsa", (request,), 10_000_000_000)
            .await
            .map_err(|e| format!("Failed to call sign_with_ecdsa {}", e.1))?;

    Ok(res.signature)
}

#[update]
async fn issue(kind: String) -> Result<String, String> {
    
    let pk = PUB_KEY.with(|pk| pk.borrow().clone());
   
    let mut claims = Claims {
        iss: None,
        sub: ic_cdk::api::caller().to_text(),
    };

    let token_kind = TokenKind::from_str(&kind).map_err(|_e| "Kind not supported")?;

    let (header, claims, signature) = match token_kind {
        TokenKind::MAC => {
            let header = Header {
                alg: format!("HS256"),
            };

            let header = base64_url::encode(&serde_json::to_string(&header).unwrap());
            let claims = base64_url::encode(&serde_json::to_string(&claims).unwrap());

            (
                header.clone(),
                claims.clone(),
                _sign_with_hmac(&format!("{}.{}", header, claims))?,
            )
        }
        TokenKind::TECDSA => {
            claims.iss = Some(_pub_key_to_did(pk));
            let header = Header {
                alg: format!("ES256K"),
            };

            let header = base64_url::encode(&serde_json::to_string(&header).unwrap());
            let claims = base64_url::encode(&serde_json::to_string(&claims).unwrap());

            (
                header.clone(),
                claims.clone(),
                _sign_with_tecdsa(&format!("{}.{}", header, claims)).await?,
            )
        }
    };

    let sig = base64_url::encode(&signature);

    Ok(format!("{}.{}.{}", header, claims, sig))
}

#[update]
async fn tecdsa_public_key(encoding: String) -> Result<String, String> {
    let pk = PUB_KEY.with(|pk| pk.borrow().clone());

    let pk = if pk.len() > 0 {
        pk
    } else {
        let pub_key = _public_key().await.unwrap().public_key;
        PUB_KEY.with(|pk| pk.replace(pub_key.clone()));
        pub_key
    };

    let encoding = PubKeyEncoding::from_str(&encoding).map_err(|_e| "Encoding not supported")?;

    let pub_key = PublicKey::from_sec1_bytes(pk.as_ref()).unwrap();
    
    match encoding {
        PubKeyEncoding::RAW => Ok(format!("{:?}", pk)),
        PubKeyEncoding::BASE58 => Ok(pk.to_base58()),
        PubKeyEncoding::JWK => Ok(pub_key.to_jwk_string()),
        PubKeyEncoding::DID_KEY => Ok(_pub_key_to_did(pk)),
    }
}
