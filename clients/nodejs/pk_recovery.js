// // recoverPub.js
// // npm install secp256k1

// const  secp = require("secp256k1") ;

// /**
//  * FILL THESE IN with the values from your Rust create_ecdsa_signature:
//  * - msgHash: the 32-byte Keccak256 hash you signed (hex, no 0x prefix)
//  * - r: first 32 bytes of the signature (hex, no 0x prefix)
//  * - s: second 32 bytes of the signature (hex, no 0x prefix)
//  * - recoveryId: the i32 you got from RecoveryId::to_i32() (0 or 1)
//  */
// //FIRST 
// //msgHash = 0x3e540787c1d9af94eb31bb7f64bf140880121aa598b3c16f6aa13d62a6926fad
// //r = 0x24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c
// //s = 0x78ec661275a1d5bb96c0021136078b7baec2aa0be2cc32a930d98adcb38f9e31
// //rid = 1
// //pk = 0x0e30091F35adc77484D8ff08674C6EA9843fDaa3

// //SECOND
// //msgHash = 0x650fa9ce0a02c5c585bc738b171505dd65efe025cded28dd08e3c90c1734a02d
// //r = 0x24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c
// //s = 0x789b0cdbba7c951a833fe180a3277b486c9916089093ca009875cf23d6fbce32
// //rid = 1
// //pk = 0x0e30091F35adc77484D8ff08674C6EA9843fDaa3


// //0x7514B93c229ADf3670EfcaB5ACbAc4ed791201F2
// //0x1B1710292EB1B6577bf2F655674e710759E2Ee14
// const msgHash     = Buffer.from("650fa9ce0a02c5c585bc738b171505dd65efe025cded28dd08e3c90c1734a02d", "hex");
// const rBuf        = Buffer.from("0424653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab", "hex");
// const sBuf        = Buffer.from("42913906595d33bfa601621dc368e7d76bb4e0d628b30b4f6406e340d456f5ab", "hex");
// const recoveryId  = 0;

// // build the 64-byte compact sig
// const sigBuf = Buffer.concat([ rBuf, sBuf ]);

// // recover the uncompressed 65-byte public key (0x04 ‖ X ‖ Y)
// const pubkey = secp.ecdsaRecover(
//   sigBuf,
//   recoveryId,
//   msgHash,
//   /* compressed = */ false
// );

// const { computeAddress } = require("ethers");

// // Convert the Buffer to a hex string with '0x' prefix
// const publicKeyHex = "0x" + Buffer.from(pubkey).toString("hex");
// console.log("Recovered public key:", publicKeyHex);

// // Now pass the hex string to computeAddress
// try {
//   const address = computeAddress(publicKeyHex);
//   console.log("Ethereum address (20 bytes):", address);
// } catch (e) {
//   console.error("Failed to compute address:", e);
// }



const secp = require("secp256k1");
const { computeAddress } = require("ethers");

// Using your SECOND dataset (corrected)
const msgHash = Buffer.from("3e540787c1d9af94eb31bb7f64bf140880121aa598b3c16f6aa13d62a6926fad", "hex");
const rBuf = Buffer.from("0424653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab", "hex"); // ✅ Fixed
const sBuf = Buffer.from("423fdfcf9e37f31e9281418d3088d7a4298b4cd2d67aa2a6cba32787f7c325ac", "hex"); // ✅ Fixed  
const recoveryId = 1; // ✅ Your SECOND dataset uses rid = 1

console.log("Input validation:");
console.log(`msgHash length: ${msgHash.length} bytes (should be 32)`);
console.log(`rBuf length: ${rBuf.length} bytes (should be 32)`);
console.log(`sBuf length: ${sBuf.length} bytes (should be 32)`);
console.log(`recoveryId: ${recoveryId}`);

// Build the 64-byte compact signature
const sigBuf = Buffer.concat([rBuf, sBuf]);
console.log(`Signature length: ${sigBuf.length} bytes (should be 64)`);

try {
    // Recover the uncompressed 65-byte public key
    const pubkey = secp.ecdsaRecover(
        sigBuf,
        recoveryId,
        msgHash,
        false // uncompressed
    );
    
    const publicKeyHex = "0x" + Buffer.from(pubkey).toString("hex");
    console.log("Recovered public key:", publicKeyHex);
    
    // Compute Ethereum address
    const address = computeAddress(publicKeyHex);
    console.log("Ethereum address:", address);
    
    // Expected result for your SECOND dataset:
    console.log("Expected public key starts with: 0x04..."); // Should be 65 bytes
    
} catch (error) {
    console.error("Recovery failed:", error.message);
}