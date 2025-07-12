import { ethers } from 'ethers';

// Replace with your EVM RPC URL (Infura, Alchemy, QuickNode, etc.)
const RPC_URL = "https://rpc-stage.devdomain123.com";

// Replace with your signed transaction (raw hex)
const signedTx = "0xa939c15af7314af9cb4ba24c4a597d68cd7ac9ab57ea85a58d80fc7923958e3a4b597aa9676312236124f215fae39d40";

// Create provider
const provider = new ethers.JsonRpcProvider(RPC_URL);

async function broadcastTransaction() {
  try {
    // send the raw signed tx, returns the txHash
    const txHash = await provider.send("eth_sendRawTransaction", [
      signedTx, 
    ]);

    console.log("📤 Sent, hash =", txHash);

    // then await confirmation
    const receipt = await provider.waitForTransaction(txHash);
    console.log("✅ Mined in block", receipt.blockNumber);
  } catch (e) {
    console.error("Broadcast failed:", e);
  }
}

broadcastTransaction();