// btc_from_sig.mjs  (ESM)
// Derive BTC addresses from ECDSA (v,r,s) + 32-byte digest (BIP-143 for P2WPKH).
import { createHash } from "crypto";
import { Buffer } from "buffer";
import * as secp from "@noble/secp256k1";

// ---------- small utils ----------
const hexToBytes = (hex) => {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (h.length % 2) throw new Error("hex length must be even");
  return Uint8Array.from(h.match(/.{1,2}/g).map((b) => parseInt(b, 16)));
};
const bytesToHex = (u8) => Buffer.from(u8).toString("hex");
const sha256 = (b) => createHash("sha256").update(b).digest();
const ripemd160 = (b) => createHash("ripemd160").update(b).digest();
const hash160 = (b) => ripemd160(sha256(b));

// ---------- base58check (P2PKH) ----------
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58encode(buf) {
  let zeros = 0;
  for (; zeros < buf.length && buf[zeros] === 0; zeros++);
  let x = BigInt("0x" + buf.toString("hex"));
  let out = "";
  while (x > 0n) { out = B58[Number(x % 58n)] + out; x /= 58n; }
  for (let i = 0; i < zeros; i++) out = "1" + out;
  return out || "1";
}
const base58check = (payload) => {
  const chk = sha256(sha256(payload)).subarray(0, 4);
  return base58encode(Buffer.concat([payload, chk]));
};

// ---------- bech32 (P2WPKH v0) ----------
const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const hrpExpand = (hrp) => {
  const hi = [], lo = [];
  for (let i = 0; i < hrp.length; i++) { const c = hrp.charCodeAt(i); hi.push(c >> 5); lo.push(c & 31); }
  return [...hi, 0, ...lo];
};
const polymod = (vals) => {
  let chk = 1;
  for (const v of vals) {
    const b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i];
  }
  return chk >>> 0;
};
const bech32CreateChecksum = (hrp, data) => {
  const vals = [...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  const mod = polymod(vals) ^ 1;
  return Array.from({ length: 6 }, (_, i) => (mod >> (5 * (5 - i))) & 31);
};
const bech32Encode = (hrp, data) => {
  const chk = bech32CreateChecksum(hrp, data);
  const combined = [...data, ...chk];
  return hrp + "1" + combined.map((v) => CHARSET[v]).join("");
};
function convertBits(data, from, to, pad = true) {
  let acc = 0, bits = 0, ret = [], maxv = (1 << to) - 1;
  for (const value of data) {
    if (value < 0 || (value >> from) !== 0) return null;
    acc = (acc << from) | value; bits += from;
    while (bits >= to) { bits -= to; ret.push((acc >> bits) & maxv); }
  }
  if (pad) { if (bits) ret.push((acc << (to - bits)) & maxv); }
  else if (bits >= from || ((acc << (to - bits)) & maxv)) { return null; }
  return ret;
}
const p2wpkhAddress = (pubkey33, network = "testnet") => {
  // Deprecated - keeping for compatibility but not used
  const hrp = network === "mainnet" ? "bc" : "tb";
  const h160 = hash160(Buffer.from(pubkey33));
  const words = convertBits(h160, 8, 5, true);
  words.unshift(0); // witness version 0
  return bech32Encode(hrp, words);
};
const p2pkhAddress = (pubkey33, network = "testnet") => {
  const prefix = network === "mainnet" ? 0x00 : 0x6f;
  const payload = Buffer.concat([Buffer.from([prefix]), hash160(Buffer.from(pubkey33))]);
  return base58check(payload);
};

// ---------- core logic ----------
/**
 * Recover compressed pubkey from (v,r,s) and 32-byte digest.
 * @param {{v:number, rHex:string, sHex:string, digestHex:string}} p
 * @returns {Promise<Uint8Array>} 33-byte compressed pubkey
 */
export async function recoverPubkeyFromVRS({ v, rHex, sHex, digestHex }) {
  const r = hexToBytes(rHex), s = hexToBytes(sHex), digest = hexToBytes(digestHex);
  if (r.length !== 32 || s.length !== 32 || digest.length !== 32) {
    throw new Error("r, s, and digest must be 32 bytes each (hex).");
  }
  if (![0, 1, 2, 3].includes(Number(v))) throw new Error("v (recovery id) must be 0..3.");
  const compactSig = new Uint8Array(64);
  compactSig.set(r, 0); compactSig.set(s, 32);
  const pub = secp.recoverPublicKey(digest, compactSig, v, true); // compressed
  // sanity verify (strict => low-S)
  const ok = secp.verify(compactSig, digest, pub, { strict: true });
  if (!ok) throw new Error("Recovered pubkey failed ECDSA verification. Check digest and v/r/s.");
  return pub;
}

/**
 * Derive BTC addresses from (v,r,s) + digest.
 * Only returns P2PKH (legacy) addresses as per new requirements.
 * @param {{v:number, rHex:string, sHex:string, digestHex:string, network?:'testnet'|'mainnet'}} p
 * @returns {Promise<{pubkeyHex:string, p2pkh:string}>}
 */
export async function deriveAddressesFromSig({ v, rHex, sHex, digestHex, network = "testnet" }) {
  const pub = await recoverPubkeyFromVRS({ v, rHex, sHex, digestHex });
  const pubkeyHex = bytesToHex(pub);
  const p2pkh = p2pkhAddress(pub, network);
  // Only return P2PKH address - P2WPKH is no longer supported
  return { pubkeyHex, p2pkh };
}

// ----- example (comment/remove in production) -----
const v = 1;
const rHex = "24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c";
const sHex = "5df715ed7b95a8fa0e82c24da7a563581dbcf7cbb30a98b3f7d1c5eae5486a55";
const digestHex = "33d24e7f6e7853787083de954b22b464da13e844331c3d639a7bb74a0612bb50";
console.log(await deriveAddressesFromSig({ v, rHex, sHex, digestHex, network: "testnet" }));
