// npm install bitcoinjs-lib node-fetch
// btc-testnet-dynamic.js
import * as bitcoin from 'bitcoinjs-lib';
import ECPairFactory from 'ecpair';
import * as tinysecp from 'tiny-secp256k1';
import fetch from 'node-fetch';
const ECPair = ECPairFactory(tinysecp);

const network = bitcoin.networks.testnet;

// ======= USER CONFIG ======= //
const senderWIF = "91ty7FQ4Xs2HnoccCuKZY8RF3yX6ZWCegmBxGDdxsRy6CBrnVDb"; // Your testnet private key in WIF
const recipientAddress = "tb1q6tamfjpxqxlq69v3ddw73fczvety79xzw56lvz"; // Where to send
const amountToSend = 1000; // satoshis - reduced to fit available balance

// Create key pair with compressed public key
const keyPair = ECPair.fromWIF(senderWIF, network);

// Force compressed public key if it's not already
const compressedKeyPair = keyPair.compressed ? keyPair : ECPair.fromPrivateKey(keyPair.privateKey, { compressed: true, network });

// Convert Uint8Array to Buffer if needed for public key
const pubkeyBuffer = Buffer.isBuffer(compressedKeyPair.publicKey) ? 
  compressedKeyPair.publicKey : 
  Buffer.from(compressedKeyPair.publicKey);

// Create a wrapper key pair that ensures all methods return Buffers
const bufferKeyPair = {
  publicKey: pubkeyBuffer,
  privateKey: Buffer.isBuffer(compressedKeyPair.privateKey) ? 
    compressedKeyPair.privateKey : 
    Buffer.from(compressedKeyPair.privateKey),
  compressed: compressedKeyPair.compressed,
  network: compressedKeyPair.network,
  sign: (hash) => {
    const signature = compressedKeyPair.sign(hash);
    return Buffer.isBuffer(signature) ? signature : Buffer.from(signature);
  },
  verify: compressedKeyPair.verify.bind(compressedKeyPair)
};

const { address } = bitcoin.payments.p2wpkh({ 
  pubkey: bufferKeyPair.publicKey, 
  network 
});

// Use the derived address as the sender address
const senderAddress = address;

console.log("Derived address from WIF:", address);
console.log("Using this as sender address");
console.log("Public key length:", bufferKeyPair.publicKey.length); // Should be 33 for compressed
console.log("Public key type:", bufferKeyPair.publicKey.constructor.name); // Should be Buffer

// =========================== //

async function getUTXOs(address) {
  const res = await fetch(`https://blockstream.info/testnet/api/address/${address}/utxo`);
  return res.json();
}

async function getRawTx(txid) {
  const res = await fetch(`https://blockstream.info/testnet/api/tx/${txid}/raw`);
  return res.text();
}

(async () => {
  try {
    // 1️⃣ Fetch UTXOs
    const utxos = await getUTXOs(senderAddress);
    if (utxos.length === 0) {
      throw new Error("No UTXOs found for address: " + senderAddress);
    }

    // Pick first UTXO
    const utxo = utxos[0];
    const prevTxId = utxo.txid;
    const vout = utxo.vout;

    console.log("Using UTXO:", prevTxId, "vout:", vout, "value:", utxo.value);

    // 2️⃣ Fetch raw transaction (optional - we're using witnessUtxo)
    // const prevTxHex = await getRawTx(prevTxId);

    // 3️⃣ Build PSBT
    const psbt = new bitcoin.Psbt({ network });
    psbt.addInput({
      hash: "04fa66ae927cd7687fb2d08a26cec41495fb6562800f7d01f85f57e9f4d3403c",
      index: vout,
      witnessUtxo: {
        script: bitcoin.address.toOutputScript(senderAddress, network),
        value: utxo.value,
      },
    });

    // 4️⃣ Add recipient output
    psbt.addOutput({
      address: recipientAddress,
      value: amountToSend,
    });

    // 5️⃣ Add change output if any
    const fee = 200; // sats (adjust)
    const change = utxo.value - amountToSend - fee;
    
    console.log(`Transaction summary:
      Input: ${utxo.value} sats
      Output to recipient: ${amountToSend} sats
      Change: ${change} sats
      Fee: ${fee} sats`);

    if (change < 0) {
      throw new Error(`Insufficient funds! Need ${amountToSend + fee} sats but only have ${utxo.value} sats`);
    }

    if (change > 0) {
      psbt.addOutput({
        address: senderAddress,
        value: change,
      });
    }

    // 6️⃣ Sign & finalize
    psbt.signInput(0, bufferKeyPair);
    
    // Validate signatures with validator function
    const validator = (pubkey, msghash, signature) => {
      return ECPair.fromPublicKey(pubkey, { network }).verify(msghash, signature);
    };
    
    psbt.validateSignaturesOfAllInputs(validator);
    psbt.finalizeAllInputs();

    // Get raw tx & txid
    const tx = psbt.extractTransaction();
    console.log("Raw TX:", tx.toHex());
    console.log("TXID:", tx.getId());
    
    // Extract signature from the transaction
    const input = tx.ins[0];
    if (input.witness && input.witness.length > 0) {
      const signature = input.witness[0]; // First element is the signature
      const publicKey = input.witness[1]; // Second element is the public key
      
      console.log("\n=== SIGNATURE DETAILS ===");
      console.log("Signature (hex):", signature.toString('hex'));
      console.log("Signature (base64):", signature.toString('base64'));
      console.log("Signature length:", signature.length);
      console.log("Public Key (hex):", publicKey.toString('hex'));
      console.log("Public Key length:", publicKey.length);
      
      // Parse DER signature components (r, s values)
      try {
        // Bitcoin signatures are DER encoded + SIGHASH flag
        const derSig = signature.slice(0, -1); // Remove last byte (SIGHASH flag)
        const sighashFlag = signature[signature.length - 1];
        
        console.log("DER Signature (hex):", derSig.toString('hex'));
        console.log("SIGHASH Flag:", sighashFlag.toString(16));
        
        // Parse DER to get r and s values
        if (derSig[0] === 0x30) { // DER sequence tag
          let offset = 2; // Skip sequence tag and length
          
          // Parse r value
          if (derSig[offset] === 0x02) { // Integer tag
            const rLength = derSig[offset + 1];
            const r = derSig.slice(offset + 2, offset + 2 + rLength);
            offset += 2 + rLength;
            
            // Parse s value
            if (derSig[offset] === 0x02) { // Integer tag
              const sLength = derSig[offset + 1];
              const s = derSig.slice(offset + 2, offset + 2 + sLength);
              
              console.log("r value (hex):", r.toString('hex'));
              console.log("s value (hex):", s.toString('hex'));
              console.log("r length:", r.length);
              console.log("s length:", s.length);
            }
          }
        }
      } catch (parseError) {
        console.log("Could not parse DER signature:", parseError.message);
      }
    } else {
      console.log("No witness data found (legacy transaction)");
      // For legacy transactions, check scriptSig
      if (input.script && input.script.length > 0) {
        console.log("Script Sig (hex):", input.script.toString('hex'));
      }
    }
    
    console.log("\nTo broadcast this transaction, you can:");
    console.log("1. Use: https://blockstream.info/testnet/tx/push");
    console.log("2. Or use a Bitcoin testnet node");

  } catch (error) {
    console.error("Error creating transaction:", error.message);
  }
})();