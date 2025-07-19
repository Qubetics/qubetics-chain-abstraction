const secp = require("secp256k1");
const { computeAddress } = require("ethers");

// Using your SECOND dataset (corrected)
// const msgHash = Buffer.from("3e540787c1d9af94eb31bb7f64bf140880121aa598b3c16f6aa13d62a6926fad", "hex");
// const rBuf = Buffer.from("24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c", "hex"); // ✅ Fixed
// const sBuf = Buffer.from("8a0c21f53ffddcbf0bee5f7778fc248c9e061516266f553cdafeee77bcaf23a4", "hex"); // ✅ Fixed  
// const recoveryId = 1; // ✅ Your SECOND dataset uses rid = 1

const msgHash = Buffer.from("168f95e7bd7d29cfbbeca50a8b6b75dd436edc3ceab72b0afd6934ac31e81c88", "hex");
const rBuf = Buffer.from("24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c", "hex"); 
const sBuf = Buffer.from("daee5823cc31729266ff2e11915461e543a732b3a2a42e0e584feb806cfe33d0", "hex"); 
const recoveryId = 1;

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
        false
    );
    
    const publicKeyHex = "0x" + Buffer.from(pubkey).toString("hex");
    console.log("Recovered public key:", publicKeyHex);
    
    // Compute Ethereum address
    const address = computeAddress(publicKeyHex);
    console.log("Ethereum address:", address);
    
    // Expected result for your SECOND dataset:
    console.log("Expected public key starts with: 0x04...");
    
} catch (error) {
    console.error("Recovery failed:", error.message);
}