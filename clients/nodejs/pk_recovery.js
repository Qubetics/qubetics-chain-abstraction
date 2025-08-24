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

    // const msgHash = Buffer.from("3e540787c1d9af94eb31bb7f64bf140880121aa598b3c16f6aa13d62a6926fad", "hex");
    // const rBuf = Buffer.from("24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c", "hex"); // ✅ Fixed 
    // const sBuf = Buffer.from("138ef152e521cb510c89b1087719eb4b1bbd8bbeeaf310972b621d791a0cc2ef", "hex"); // ✅ Fixed  
    // const recoveryId = 0; // ✅ Your SECOND dataset uses rid = 1
    //1 => 0x080cfdf386e3627C959299266698DA2b48A77E15
    //0 => 0x649D0Fac24E36532693BA146B2D77F243D419c23

    // const msgHash = Buffer.from("650fa9ce0a02c5c585bc738b171505dd65efe025cded28dd08e3c90c1734a02d", "hex");
    // const rBuf = Buffer.from("24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c", "hex"); 
    // const sBuf = Buffer.from("13e04a89a0470bf22009d19909f9fb7e5de71fc23d2b793fc3c5d931f6a092ee", "hex"); 
    // const recoveryId = 27;
    //0 => 0x61E2f29899a5e1F6662E316077528Af6b4d9517D
    //1 => 0x080cfdf386e3627C959299266698DA2b48A77E15

    const msgHash = Buffer.from("bb879616dfbf0155bcd89def7b71a3ad9972f7b473b8fcf2d12640f57f3e41e2", "hex");
    const rBuf = Buffer.from("24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c", "hex");
    const sBuf = Buffer.from("3d55be84df9d79ed1050615c8609067f67fc5b13d0e0993b209ab5410f36aeb5", "hex");
    const recoveryId = 0;
    //0 => 0x080cfdf386e3627C959299266698DA2b48A77E15


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