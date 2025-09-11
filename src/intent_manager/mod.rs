use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, Result};
use ethers::{
    abi::{Abi, Token},
    providers::{Http, Provider, Middleware},
    types::{
        transaction::eip1559::Eip1559TransactionRequest,
        transaction::eip2718::TypedTransaction,
        Address, BlockId, BlockNumber, Bytes, H256, U256, U64, NameOrAddress,
    },
};
use rlp::RlpStream;
use serde_json;
use secp256k1::{self, ecdsa::RecoverableSignature, Message, PublicKey, Secp256k1, SecretKey};

// ===== ABI LOADER (keep your ABI file next to this source) =====
static ABI: OnceLock<Abi> = OnceLock::new();
fn intent_manager_abi() -> &'static Abi {
    ABI.get_or_init(|| {
        serde_json::from_str(include_str!("intent_manager_abi.json"))
            .expect("invalid ABI JSON")
    })
}

/// Build a ready-to-sign EIP-1559 tx for a contract function and return:
///  - sighash: what your MPC signs
///  - unsigned_preimage_hex: 0x02 || RLP([...]) as hex
///  - tx: TypedTransaction to combine later with (r,s,v) in your own finalizer
pub async fn prepare_unsigned_eip1559_tx(
    provider: Arc<Provider<Http>>,
    chain_id: u64,
    from: Address,
    to: Address,                // contract address
    function_name: &str,
    params: Vec<Token>,         // ABI-typed params
    value: Option<U256>,        // wei (None for non-payable)
    manual_gas: Option<U256>,   // if None -> estimate
    manual_max_fee: Option<U256>,
    manual_max_priority: Option<U256>,
) -> Result<(H256, String, TypedTransaction)> {
    // 1) calldata
    let f = intent_manager_abi().function(function_name)?;
    let data = Bytes::from(f.encode_input(&params)?);

    // 2) skeleton
    let mut req = Eip1559TransactionRequest::new()
        .from(from)
        .to(to)
        .data(data)
        .chain_id(U64::from(chain_id));
    if let Some(v) = value { req = req.value(v); }

    // 3) nonce
    let nonce = provider.as_ref().get_transaction_count(from, None).await?;
    req = req.nonce(nonce);

    // 4) gas
    if let Some(g) = manual_gas {
        req = req.gas(g);
    } else {
        let mut tmp = TypedTransaction::Eip1559(req.clone());
        let g = provider.as_ref().estimate_gas(&tmp, None).await?;
        req = req.gas(g);
    }

    // 5) fees
    let (max_fee, max_prio) = derive_fees(provider.as_ref(), manual_max_fee, manual_max_priority).await?;
    req = req.max_fee_per_gas(max_fee).max_priority_fee_per_gas(max_prio);

    // 6) final tx + sighash
    let tx = TypedTransaction::Eip1559(req.clone());
    let sighash = tx.sighash(); // includes chain_id for type-2

    // 7) unsigned preimage (0x02 || RLP([...]))
    let preimage = encode_unsigned_payload_eip1559(&req)?;
    let unsigned_preimage_hex = format!("0x{}", hex::encode(preimage));

    Ok((sighash, unsigned_preimage_hex, tx))
}

// ------- internals (minimal) -------

async fn derive_fees(
    provider: &Provider<Http>,
    manual_max_fee: Option<U256>,
    manual_max_priority: Option<U256>,
) -> Result<(U256, U256)> {
    if let (Some(mf), Some(mp)) = (manual_max_fee, manual_max_priority) {
        return Ok((mf, mp));
    }
    let default_prio = U256::from(1_500_000_000u64); // ~1.5 gwei

    if let Some(block) = provider
        .get_block(BlockId::Number(BlockNumber::Latest))
        .await?
    {
        let base = block.base_fee_per_gas.unwrap_or_default();
        let prio = manual_max_priority.unwrap_or(default_prio);
        let max  = manual_max_fee.unwrap_or(base * 2 + prio);
        Ok((max, prio))
    } else {
        // fallback for weird RPCs
        let gp   = provider.get_gas_price().await?;
        let prio = manual_max_priority.unwrap_or(default_prio);
        Ok((gp + prio, prio))
    }
}

fn encode_unsigned_payload_eip1559(req: &Eip1559TransactionRequest) -> Result<Vec<u8>> {
    let chain_id = req.chain_id.ok_or_else(|| anyhow!("missing chain_id"))?;
    let nonce    = req.nonce.ok_or_else(|| anyhow!("missing nonce"))?;
    let max_prio = req.max_priority_fee_per_gas.ok_or_else(|| anyhow!("missing max_priority_fee_per_gas"))?;
    let max_fee  = req.max_fee_per_gas.ok_or_else(|| anyhow!("missing max_fee_per_gas"))?;
    let gas      = req.gas.ok_or_else(|| anyhow!("missing gas"))?;

    let to_ref   = req.to.as_ref().ok_or_else(|| anyhow!("missing to"))?;
    let value    = req.value.unwrap_or_default();
    let data     = req.data.clone().unwrap_or_default();

    let mut s = RlpStream::new_list(9);
    s.append(&U256::from(chain_id.as_u64()));
    s.append(&nonce);
    s.append(&max_prio);
    s.append(&max_fee);
    s.append(&gas);

    match to_ref {
        NameOrAddress::Address(a) => { s.append(a); }   // <-- do the append, then end arm
        NameOrAddress::Name(_) => return Err(anyhow!("resolve ENS before encoding")),
    };                                                  // <-- END THE MATCH WITH A SEMICOLON

    s.append(&value);
    s.append(&data.as_ref());
    s.begin_list(0);

    let rlp_bytes = s.out();            // out(self) consumes s — call it ONCE
    let mut out = Vec::with_capacity(1 + rlp_bytes.len());
    out.push(0x02);
    out.extend_from_slice(&rlp_bytes);
    Ok(out)
}


pub fn sign_unsigned_preimage_to_raw_with_secp(
    unsigned_preimage_hex: &str,
    sk: &secp256k1::SecretKey,
) -> anyhow::Result<(ethers::types::Bytes, ethers::types::H256, [u8; 32], [u8; 32], u64)> {
    use anyhow::anyhow;
    use ethers::types::{H256, U256, Bytes};
    use rlp::{Rlp, RlpStream};
    use secp256k1::{ecdsa::RecoverableSignature, Message, Secp256k1};

    // 1) decode & sanity
    let pre = unsigned_preimage_hex.strip_prefix("0x").unwrap_or(unsigned_preimage_hex);
    let pre_bytes = hex::decode(pre)?;
    if pre_bytes.first().copied() != Some(0x02) {
        return Err(anyhow!("expected type-2 preimage (starts with 0x02)"));
    }
    let body = &pre_bytes[1..];
    let rlp_list = Rlp::new(body);
    if !rlp_list.is_list() {
        return Err(anyhow!("payload is not an RLP list"));
    }
    if rlp_list.item_count()? != 9 {
        return Err(anyhow!("expected 9 signing fields, got {}", rlp_list.item_count()?));
    }

    // 2) sighash = keccak256(preimage)
    let sighash = H256::from_slice(&ethers::utils::keccak256(&pre_bytes));

    // 3) sign with secp256k1 ≤0.27 API
    let secp = Secp256k1::new();
    let msg = Message::from_slice(sighash.as_bytes())?;
    let rec_sig: RecoverableSignature = secp.sign_ecdsa_recoverable(&msg, sk);

    // NOTE (≤0.27): tuple order is (RecoveryId, [u8; 64])
    let (recid, sig64) = rec_sig.serialize_compact();

    let mut r32 = [0u8; 32];
    let mut s32 = [0u8; 32];
    r32.copy_from_slice(&sig64[0..32]);
    s32.copy_from_slice(&sig64[32..64]);
    let v_parity = (recid.to_i32() & 1) as u64; // 0/1 (typed tx expects parity)

    // 4) rebuild RLP: original 9 items + v + r + s
    let mut s = RlpStream::new_list(12);
    for i in 0..9 {
        s.append_raw(rlp_list.at(i)?.as_raw(), 1);
    }
    s.append(&v_parity);
    s.append(&U256::from_big_endian(&r32));
    s.append(&U256::from_big_endian(&s32));

    // 5) final bytes = 0x02 || RLP(12 items)  (call .out() ONCE)
    let rlp_body = s.out();
    let mut out = Vec::with_capacity(1 + rlp_body.len());
    out.push(0x02);
    out.extend_from_slice(rlp_body.as_ref());

    Ok((Bytes::from(out), sighash, r32, s32, v_parity))
}
