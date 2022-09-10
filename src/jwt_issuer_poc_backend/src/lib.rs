mod signature_map;
use crate::signature_map::SignatureMap;
use base58::{ToBase58, FromBase58};
use hmac::{Hmac, Mac};
use ic_cdk::export::{
    candid::CandidType,
    serde::{Deserialize, Serialize},
    Principal,
};

use ic_cdk_macros::{query, update};
use ic_certified_map::{labeled_hash, HashTree};
use k256::PublicKey;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use std::{borrow::Borrow, cell::RefCell};
use std::{convert::TryInto, str::FromStr};

const fn secs_to_nanos(secs: u64) -> u64 {
    secs * 1_000_000_000
}
// 30 mins
const DEFAULT_EXPIRATION_PERIOD_NS: u64 = secs_to_nanos(30 * 60);

const LABEL_SIG: &[u8] = b"sig";

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
    ICCSA,
}

impl FromStr for TokenKind {
    type Err = ();

    fn from_str(input: &str) -> Result<TokenKind, Self::Err> {
        match input {
            "mac" => Ok(TokenKind::MAC),
            "tecdsa" => Ok(TokenKind::TECDSA),
            "iccsa" => Ok(TokenKind::ICCSA),
            _ => Err(()),
        }
    }
}

enum PubKeyEncoding {
    RAW,
    BASE58,
    JWK,
    DIDKEY,
}

impl FromStr for PubKeyEncoding {
    type Err = ();

    fn from_str(input: &str) -> Result<PubKeyEncoding, Self::Err> {
        match input {
            "raw" => Ok(PubKeyEncoding::RAW),
            "base58" => Ok(PubKeyEncoding::BASE58),
            "jwk" => Ok(PubKeyEncoding::JWK),
            "did_key" => Ok(PubKeyEncoding::DIDKEY),
            _ => Err(()),
        }
    }
}

thread_local! {

    static MAC_KEY: Hmac<Sha256> = Hmac::new_from_slice(b"some-secret").unwrap();
    static PUB_KEY: RefCell<Vec<u8>> = RefCell::new(vec![]);
    static SIGS: RefCell<SignatureMap> = RefCell::new(SignatureMap::default())
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

fn update_root_hash(m: &SignatureMap) {
    ic_cdk::api::set_certified_data(&labeled_hash(LABEL_SIG, &m.root_hash())[..]);
}

fn _sign_with_iccsa(msg: &str) -> Result<Vec<u8>, String> {
    let mut hasher = Sha256::new();
    hasher.update(msg);
    let hashed = hasher.finalize();

    let hashed_msg = hashed.try_into().expect("Incorrect length");

    let caller = ic_cdk::caller().clone();
    let seed = caller.as_slice();

    let mut hasher = Sha256::new();
    hasher.update(seed);
    let hashed_seed = hasher.finalize().try_into().expect("Incorrect size");

    let expires_at = (ic_cdk::api::time() as u64) + DEFAULT_EXPIRATION_PERIOD_NS;

    SIGS.with(|s| {
        let mut sigs = s.borrow_mut();
        sigs.put(hashed_seed, hashed_msg, expires_at);
        update_root_hash(&sigs);
    });

    let sig = [hashed_seed, hashed_msg].concat();

    Ok(sig)
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
        TokenKind::ICCSA => {
            claims.iss = Some(ic_cdk::api::id().to_text());
            let header = Header {
                alg: format!("ICCSA"),
            };

            let header = base64_url::encode(&serde_json::to_string(&header).unwrap());
            let claims = base64_url::encode(&serde_json::to_string(&claims).unwrap());

            (
                header.clone(),
                claims.clone(),
                _sign_with_iccsa(&format!("{}.{}", header, claims))?,
            )
        }
    };

    let sig = base64_url::encode(&signature);

    Ok(format!("{}.{}.{}", header, claims, sig))
}

fn _get_iccsa(sigs: &SignatureMap, hash: [u8; 64]) -> Option<String> {
    let certificate = ic_cdk::api::data_certificate().unwrap_or_else(|| {
        ic_cdk::trap("data certificate is only available in query calls");
    });

    // Split hash in two parts

    let seed = hash[0..32].try_into().unwrap();
    let msg_hash = hash[32..64].try_into().unwrap(); 
    
    let witness = sigs.witness(seed, msg_hash)?;

    let witness_hash = witness.reconstruct();
    let root_hash = sigs.root_hash();
    if witness_hash != root_hash {
        ic_cdk::trap(&format!(
            "internal error: signature map computed an invalid hash tree, witness hash is {}, root hash is {}",
            hex::encode(&witness_hash),
            hex::encode(&root_hash)
        ));
    }

    let tree = ic_certified_map::labeled(&LABEL_SIG[..], witness);

    #[derive(Serialize)]
    struct Sig<'a> {
        certificate: ByteBuf,
        tree: HashTree<'a>,
    }

    let sig = Sig {
        certificate: ByteBuf::from(certificate),
        tree,
    };

    let mut cbor = serde_cbor::ser::Serializer::new(Vec::new());
    cbor.self_describe().unwrap();
    sig.serialize(&mut cbor).unwrap();
    Some(cbor.into_inner().to_base58())
}

#[query]
async fn get_iccsa(hash: String) -> Result<String, String> {
    let hash = base64_url::decode(&hash).expect("Couldn't base64url decode.");
    SIGS.with(|s| {
        let sigs = s.borrow();
        match _get_iccsa(&sigs, hash.try_into().expect("Incorrect size")) {
            Some(signature) => Ok(signature),
            None => Err(String::from("Couldn't find signature")),
        }
    })
   
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
        PubKeyEncoding::DIDKEY => Ok(_pub_key_to_did(pk)),
    }
}
