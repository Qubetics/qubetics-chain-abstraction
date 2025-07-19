const secp = require("secp256k1");
const { computeAddress } = require("ethers");

// Using your SECOND dataset (corrected)
const msgHash = Buffer.from("650fa9ce0a02c5c585bc738b171505dd65efe025cded28dd08e3c90c1734a02d", "hex");
const rBuf = Buffer.from("24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c", "hex"); // ✅ Fixed 
const sBuf = Buffer.from("b4b52d90fab5fd04c71db7faf1f88d85122f49195f79f78ebcc85ba0291b6590", "hex"); // ✅ Fixed  
const recoveryId = 0; // ✅ Your SECOND dataset uses rid = 1

// const msgHash = Buffer.from("168f95e7bd7d29cfbbeca50a8b6b75dd436edc3ceab72b0afd6934ac31e81c88", "hex");
// const rBuf = Buffer.from("24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c", "hex"); 
// const sBuf = Buffer.from("e0994f0e87c406fb7441289ccea3ee94397f73b4f854cddd1109e2f172d59255", "hex"); 
// const recoveryId = 0;

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