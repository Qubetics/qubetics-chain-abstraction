import secp from "secp256k1";

// Main async function to handle dynamic imports
async function main() {
    // Try to load keccak for proper Ethereum address computation
    let keccak256 = null;
    try {
        const { keccak } = await import("ethereum-cryptography/keccak");
        keccak256 = (data) => keccak(data);
    } catch (e) {
        try {
            const keccakModule = await import("keccak");
            const keccak = keccakModule.default;
            keccak256 = (data) => keccak("keccak256").update(data).digest();
        } catch (e2) {
            console.log("⚠️  Keccak library not found. Install with: npm install ethereum-cryptography");
        }
    }

    // Alternative method to compute Ethereum address
    function computeEthereumAddress(publicKeyBuffer) {
        // Remove the 0x04 prefix if present (uncompressed key indicator)
        const pubKeyBytes = publicKeyBuffer.slice(1); // Remove first byte (0x04)

        if (keccak256) {
            // Use proper Keccak-256 hash
            const hash = keccak256(pubKeyBytes);
            // Take last 20 bytes as Ethereum address
            const address = '0x' + hash.slice(-20).toString('hex');
            return address;
        } else {
            console.log("❌ Cannot compute Ethereum address without Keccak-256");
            return null;
        }
    }

    // Try ethers import as fallback
    let computeAddress = null;
    try {
        const ethers = await import("ethers");
        // Try different import patterns for different ethers versions
        if (ethers.utils && ethers.utils.computeAddress) {
            computeAddress = ethers.utils.computeAddress; // ethers v5
        } else if (ethers.computeAddress) {
            computeAddress = ethers.computeAddress; // ethers v6
        } else if (ethers.default && ethers.default.computeAddress) {
            computeAddress = ethers.default.computeAddress; // ethers v6 default export
        }
    } catch (e) {
        console.log("⚠️  Ethers not available. Install with: npm install ethers");
    }

    console.log("\n📦 Dependency Status:");
    console.log(`✅ secp256k1: Available`);
    console.log(`${keccak256 ? '✅' : '❌'} keccak256: ${keccak256 ? 'Available' : 'Missing - install ethereum-cryptography'}`);
    console.log(`${computeAddress ? '✅' : '❌'} ethers: ${computeAddress ? 'Available' : 'Missing - install ethers'}`);


    const msgHash = Buffer.from("08064ed6b3b4d202f22689e5268aa6a829d080f941387ab3768af592cc9ab720", "hex");
    const rBuf = Buffer.from("24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c", "hex");
    const sBuf = Buffer.from("01d87eb21ab0b24fbc9ee6b3ae15bb613be5954844fc4f467000c281622ef02a", "hex");
    const recoveryId = 1;


    console.log("\n🔍 Input validation:");
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
        console.log("\n✅ Recovered public key:", publicKeyHex);

        // Compute Ethereum address using available method
        let address = null;
        if (computeAddress) {
            try {
                address = computeAddress(publicKeyHex);
                console.log("🏦 Ethereum address (via ethers):", address);
            } catch (e) {
                console.log("❌ Ethers computeAddress failed:", e.message);
            }
        }

        if (!address && keccak256) {
            address = computeEthereumAddress(Buffer.from(pubkey));
            if (address) {
                console.log("🏦 Ethereum address (manual computation):", address);
            }
        }

        if (!address) {
            console.log("❌ Could not compute Ethereum address. Install dependencies:");
            console.log("   npm install ethers");
            console.log("   npm install ethereum-cryptography");
        }

        // Expected result for your SECOND dataset:
        console.log("\n📋 Expected public key starts with: 0x04...");

    } catch (error) {
        console.error("❌ Recovery failed:", error.message);
    }

    console.log("\n💡 If you're missing dependencies, run:");
    console.log("   npm install ethers ethereum-cryptography");
}

// Run the main function
main().catch(console.error);