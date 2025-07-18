// walkthrough.js
import * as secp from "@noble/secp256k1";
import {
  JsonRpcProvider,
  parseEther,
  parseUnits,
  keccak256,
  recoverAddress,
  computeAddress,
  getAddress,
  Transaction
} from "ethers";

// ——— Helpers ———

// Convert BigInt → 32-byte big-endian Uint8Array
function bigIntTo32Bytes(num) {
  const hex = num.toString(16).padStart(64, "0");
  return Uint8Array.from(Buffer.from(hex, "hex"));
}
// Convert BigInt → 0x-prefixed 64-char hex string
function toHex32(num) {
  return "0x" + num.toString(16).padStart(64, "0");
}
// Extended-Euclid modular inverse
function modInv(a, m = secp.CURVE.n) {
  let [old_r, r] = [a < 0n ? ((a % m) + m) % m : a, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return old_s < 0n ? old_s + m : old_s;
}
// Compute Lagrange coefficient λᵢ at x=0
function lagrangeCoeff(i, xs) {
  const n = secp.CURVE.n;
  let num = 1n, den = 1n;
  for (const j of xs) {
    if (j !== i) {
      num = (num * (0n - j)) % n;
      den = (den * (i - j)) % n;
    }
  }
  return (num * modInv(den, n)) % n;
}

// ——— Shamir shares ———
// Replace these with your real DKG shares (32-byte hex → BigInt)
const SHARES = [
  { x: 1n, share: BigInt("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") },
  { x: 2n, share: BigInt("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB") },
  { x: 3n, share: BigInt("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC") },
];

// ——— Threshold-Schnorr signing ———
async function thresholdSign(msgHashHex) {
  const n = secp.CURVE.n;

  // 1) Aggregate public key: Σᵢ λᵢ·(shareᵢ·G)
  const xs = SHARES.map(s => s.x);
  let agg = null;
  for (const { x, share } of SHARES) {
    const λ = lagrangeCoeff(x, xs);
    const Pi = secp.Point.fromHex(secp.getPublicKey(bigIntTo32Bytes(share), true));
    agg = agg ? agg.add(Pi.multiply(λ)) : Pi.multiply(λ);
  }

  // 2) Aggregate nonces R = Σ Rᵢ, r = R.x mod n
  const nonces = SHARES.map(() => secp.utils.randomPrivateKey());
  const Rpts   = nonces.map(kb => secp.Point.fromHex(secp.getPublicKey(kb, true)));
  const R      = Rpts.reduce((a, b) => a.add(b));
  const r      = R.x % n;

  // 3) e = keccak256(r || msg)
  const msgBuf = Buffer.from(msgHashHex.slice(2), "hex");
  const data   = Buffer.concat([bigIntTo32Bytes(r), msgBuf]);
  const e      = BigInt(keccak256(data));

  // 4) sᵢ = kᵢ + e·shareᵢ, then s = Σ sᵢ mod n
  const s = SHARES
    .map(({ share }, i) => {
      const k_i = BigInt("0x" + Buffer.from(nonces[i]).toString("hex"));
      return (k_i + e * share) % n;
    })
    .reduce((acc, si) => (acc + si) % n, 0n);

  // Return r, s and uncompressed pubkey ("0x04…" form)
  return {
    r,
    s,
    groupPublicKey: "0x" + agg.toHex(false)
  };
}

// ——— Main flow ———
async function main() {
  // 1) Provider (ENS disabled)
  const provider = new JsonRpcProvider(
    "https://rpc-stage.devdomain123.com",
    { chainId: 1043, name: "customchain", ensAddress: null }
  );

  // 2) Derive threshold public key & fromAddress
  const { groupPublicKey } = await thresholdSign("0x");      // dummy hash → only pubkey
  const fromAddress       = getAddress(computeAddress(groupPublicKey));

  // 3) Fetch nonce for that address
  const nonce = await provider.getTransactionCount(fromAddress);

  // 4) Build unsigned tx request
  const txRequest = {
    to:       "0xabcdef0000000000000000000000000000000000",   // all lowercase
    value:    parseEther("0.001"),
    gasLimit: 21000,
    gasPrice: parseUnits("20", "gwei"),
    nonce,
    chainId:  1043
  };

  // 5) Serialize & hash
  const unsignedTx = Transaction.from(txRequest);
  const msgHash    = unsignedTx.unsignedHash;

  // 6) Threshold-sign on real msgHash
  let { r, s } = await thresholdSign(msgHash);

  // 7) Enforce low-s (canonical ECDSA)
  const HALF_ORDER = secp.CURVE.n >> 1n;
  if (s > HALF_ORDER) {
    s = secp.CURVE.n - s;
  }

  // 8) Recover correct v (27 or 28)
  let v;
  for (let recId = 0; recId < 2; recId++) {
    const cand = recId + 27;
    try {
      const addr = recoverAddress(msgHash, { r: toHex32(r), s: toHex32(s), v: cand });
      if (addr.toLowerCase() === fromAddress.toLowerCase()) {
        v = cand;
        break;
      }
    } catch {}
  }
  if (v == null) throw new Error("Could not derive v");

  // 9) Build signed tx and broadcast
  const signedTx = Transaction.from({ ...txRequest, v, r: toHex32(r), s: toHex32(s) });
  const resp     = await provider.broadcastTransaction(signedTx.serialized);
  console.log("✅ Tx sent:", resp.hash);
}

main().catch(err => {
  console.error("🔥 Fatal:", err);
  process.exit(1);
});
