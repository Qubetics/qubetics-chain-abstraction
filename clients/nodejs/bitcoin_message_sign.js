import * as bitcoin from 'bitcoinjs-lib';
import ECPairFactory from 'ecpair';
import * as secp from 'tiny-secp256k1';
import { createHash } from 'crypto';
import { Buffer } from 'buffer';

const ECPair = ECPairFactory(secp);
const network = bitcoin.networks.testnet;
const senderWIF = "91ty7FQ4Xs2HnoccCuKZY8RF3yX6ZWCegmBxGDdxsRy6CBrnVDb";
const keyPair = ECPair.fromWIF(senderWIF, network);

// cPj3yo35oQUof1S9nzFKRrvfDjW3uZLPSxNeUZiE9Sw1gCZhyCPT
// 91ty7FQ4Xs2HnoccCuKZY8RF3yX6ZWCegmBxGDdxsRy6CBrnVDb
// cQYXjsxUtPVztLZgLcwbPURjn8jMK2JC6HXt7nJrbUwmGsCPPG7w

function sha256(buffer) { 
  return createHash('sha256').update(buffer).digest(); 
}
function hashMessage(msg) { 
  return sha256(sha256(Buffer.from(msg, 'utf8'))); 
}

const message = "hello";
const messageHash = hashMessage(message);
console.log("Message Hash (hex):", messageHash.toString('hex'));

// --- SIGN WITH RECOVERY ID ---
const sig65 = secp.signRecoverable(messageHash, keyPair.privateKey); // 65-byte Buffer


// Convert to array of bytes
const sigArray = Array.from(sig65);

console.log("Recoverable Signature (bytes array):", sig65);
console.log("Length:", sigArray.length); // should be 65

// Extract r, s, recoveryId if needed
// const r = sig65.slice(0, 32);
// const s = sig65.slice(32, 64);
const recoveryId = sig65[64];

// console.log("r (hex):", r.toString('hex'));
// console.log("s (hex):", s.toString('hex'));
console.log("recoveryId:", recoveryId);

// --- RECOVER PUBLIC KEY ---
// const recoveredPubKey = secp.recover(messageHash, sig65.slice(0, 64), recoveryId, true);
// console.log("Recovered PubKey (hex):", Buffer.from(recoveredPubKey).toString('hex'));
// console.log("Matches original?", Buffer.from(recoveredPubKey).equals(keyPair.publicKey));
