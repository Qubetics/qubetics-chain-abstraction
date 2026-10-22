import dotenv from 'dotenv';
import { ethers } from 'ethers';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load .env from project root (two levels up)
dotenv.config({ path: join(__dirname, '../../.env') });

// -------- CONFIG --------
const RPC_URL = process.env.SOLVER_CONTRACT_RPC_URL;
const INTENT_MANAGER_ADDRESS = '0x48E858AF5Ed706Aa72e27D957442491761a5e540';
const TX_SENDER_PK = '4289ba4c078eb7c639b72f3b253e03fe6420d64a3e2f60b2a6f6046b9e6d5010';

if (!RPC_URL) throw new Error("SOLVER_CONTRACT_RPC_URL not set in .env");
if (!INTENT_MANAGER_ADDRESS) throw new Error("INTENT_MANAGER_CONTRACT_ADDRESS not set in .env");
if (!TX_SENDER_PK) throw new Error("TX_SENDER_PK not set in .env");

const provider = new ethers.providers.JsonRpcProvider(RPC_URL);
const wallet = new ethers.Wallet(TX_SENDER_PK, provider);

// -------- ABI (only what we need) --------
const ABI = [
  // Enums: BatchType { BTC=0, TICS=1 }
  `function processBatchIntents(
    tuple(
      string sourceAddress,
      string targetAddress,
      string sourceChain,
      string targetChain,
      uint128 sourceAmount,
      uint128 targetAmount,
      string sourceToken,
      string targetToken,
      string intentId,
      string withdrawTxHash,
      string depositTxHash
    )[] batchIntents,
    uint8 batchType,
    string timestamp
  )`,
  "function getIntent(string) view returns (tuple(string,string,string,string,uint128,uint128,string,string,string,string,string))",
  "function intentExists(string) view returns (bool)",
  "function getAllIntentIds() view returns (string[])",
  "function version() view returns (string)",
  "function solverManager() view returns (address)",
  "function treasuryVault() view returns (address)",
  "function setSolverManager(address)",
  "function setTreasuryVault(address)",
];

const intentManager = new ethers.Contract(INTENT_MANAGER_ADDRESS, ABI, provider);

// -------- BATCH TYPE ENUM --------
const BatchType = {
  BTC: 0,
  TICS: 1,
};

// =====================================================
// HELPER: Build a single BatchIntentInput
// =====================================================
function buildIntent({
  sourceAddress,
  targetAddress,
  sourceChain,
  targetChain,
  sourceAmount,
  targetAmount,
  sourceToken,
  targetToken,
  intentId,
  withdrawTxHash = "",
  depositTxHash = "",
}) {
  return {
    sourceAddress,
    targetAddress,
    sourceChain,
    targetChain,
    sourceAmount,
    targetAmount,
    sourceToken,
    targetToken,
    intentId,
    withdrawTxHash,
    depositTxHash,
  };
}

// =====================================================
// SEND processBatchIntents TRANSACTION
// =====================================================
async function processBatchIntents(batchIntents, batchType, timestamp) {
  console.log(`\n📦 Calling processBatchIntents with ${batchIntents.length} intent(s)\n`);
  console.log(`   Batch Type: ${batchType === BatchType.BTC ? "BTC" : "TICS"}`);
  console.log(`   Timestamp:  ${timestamp}\n`);

  // Log each intent
  batchIntents.forEach((intent, i) => {
    console.log(`   Intent ${i + 1}:`);
    console.log(`     intentId:       ${intent.intentId}`);
    console.log(`     sourceAddress:  ${intent.sourceAddress}`);
    console.log(`     targetAddress:  ${intent.targetAddress}`);
    console.log(`     sourceChain:    ${intent.sourceChain}`);
    console.log(`     targetChain:    ${intent.targetChain}`);
    console.log(`     sourceAmount:   ${intent.sourceAmount}`);
    console.log(`     targetAmount:   ${intent.targetAmount}`);
    console.log(`     sourceToken:    ${intent.sourceToken}`);
    console.log(`     targetToken:    ${intent.targetToken}`);
    console.log(`     withdrawTxHash: ${intent.withdrawTxHash}`);
    console.log(`     depositTxHash:  ${intent.depositTxHash}`);
    console.log();
  });

  try {
    // Estimate gas first
    const intentManagerWithSigner = intentManager.connect(wallet);

    console.log("   Estimating gas...");
    const gasEstimate = await intentManagerWithSigner.estimateGas.processBatchIntents(
      batchIntents,
      batchType,
      timestamp
    );
    console.log(`   Gas estimate: ${gasEstimate.toString()}\n`);

    console.log("   Sending transaction...\n");
    const tx = await intentManagerWithSigner.processBatchIntents(
      batchIntents,
      batchType,
      timestamp,
      { gasLimit: gasEstimate.mul(120).div(100) } // 20% buffer
    );

    console.log(`   Transaction Hash: ${tx.hash}`);
    console.log("   Waiting for confirmation...\n");

    const receipt = await tx.wait();
    console.log(`   Status:      ${receipt.status === 1 ? "SUCCESS" : "FAILED"}`);
    console.log(`   Block:       ${receipt.blockNumber}`);
    console.log(`   Gas Used:    ${receipt.gasUsed.toString()}`);

    // Log events
    if (receipt.logs.length > 0) {
      console.log(`   Events:      ${receipt.logs.length} event(s) emitted`);
    }

    return receipt;
  } catch (e) {
    console.error(`   Transaction failed: ${e.message}`);
    if (e.error?.data) {
      console.error(`   Revert data: ${e.error.data}`);
    }
    throw e;
  }
}

// =====================================================
// VERIFY: Check intent was stored
// =====================================================
async function verifyIntent(intentId) {
  console.log(`\n🔍 Verifying intent: ${intentId}`);
  try {
    const exists = await intentManager.intentExists(intentId);
    console.log(`   Exists: ${exists}`);

    if (exists) {
      const intent = await intentManager.getIntent(intentId);
      console.log(`   Source: ${intent[0]} -> Target: ${intent[1]}`);
      console.log(`   Chains: ${intent[2]} -> ${intent[3]}`);
      console.log(`   Amounts: ${intent[4].toString()} -> ${intent[5].toString()}`);
      console.log(`   Tokens: ${intent[6]} -> ${intent[7]}`);
      console.log(`   IntentId: ${intent[8]}`);
      console.log(`   WithdrawTx: ${intent[9]}`);
      console.log(`   DepositTx: ${intent[10]}`);
    }
    return exists;
  } catch (e) {
    console.error(`   Error: ${e.message}`);
    return false;
  }
}

// =====================================================
// MAIN
// =====================================================
async function main() {
  console.log("=".repeat(70));
  console.log("  IntentManager - processBatchIntents Script");
  console.log("=".repeat(70));

  const network = await provider.getNetwork();
  console.log(`\n   Chain ID:         ${network.chainId}`);
  console.log(`   RPC:              ${RPC_URL}`);
  console.log(`   IntentManager:    ${INTENT_MANAGER_ADDRESS}`);
  console.log(`   Wallet:           ${wallet.address}`);

  // Check contract version
  try {
    const version = await intentManager.version();
    console.log(`   Contract Version: ${version}`);
  } catch (e) {
    console.log(`   Contract Version: (could not read)`);
  }

  const balance = await provider.getBalance(wallet.address);
  console.log(`   Wallet Balance:   ${ethers.utils.formatEther(balance)} TICS`);

  // Check critical contract state
  try {
    const solverMgr = await intentManager.solverManager();
    console.log(`   SolverManager:    ${solverMgr}${solverMgr === ethers.constants.AddressZero ? " ⚠️  NOT SET!" : ""}`);
  } catch (e) {
    console.log(`   SolverManager:    (could not read)`);
  }
  try {
    const vault = await intentManager.treasuryVault();
    console.log(`   TreasuryVault:    ${vault}${vault === ethers.constants.AddressZero ? " ⚠️  NOT SET!" : ""}`);
  } catch (e) {
    console.log(`   TreasuryVault:    (could not read)`);
  }
  console.log();

  // =========================================================
  // CONFIGURE YOUR INTENTS HERE
  // =========================================================
  const batchType = BatchType.BTC; // Use BatchType.BTC or BatchType.TICS
  const timestamp = new Date().toISOString();

  const batchIntents = [
    buildIntent({
      sourceAddress: "0x1234567890abcdef1234567890abcdef12345678",
      targetAddress: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
      sourceChain: "ethereum",
      targetChain: "qubetics",
      sourceAmount: 1000000,          // uint128
      targetAmount: 950000,           // uint128
      sourceToken: "ETH",
      targetToken: "TICS",
      intentId: "intent_test_001",
      withdrawTxHash: "0xabc123withdraw",
      depositTxHash: "0xdef456deposit",
    }),
    // Add more intents as needed:
    // buildIntent({
    //   sourceAddress: "bc1qexamplebitcoinaddress",
    //   targetAddress: "0xTargetEVMAddress",
    //   sourceChain: "bitcoin",
    //   targetChain: "qubetics",
    //   sourceAmount: 50000,
    //   targetAmount: 48000,
    //   sourceToken: "BTC",
    //   targetToken: "TICS",
    //   intentId: "intent_test_002",
    //   withdrawTxHash: "btc_withdraw_hash",
    //   depositTxHash: "btc_deposit_hash",
    // }),
  ];

  // =========================================================
  // EXECUTE
  // =========================================================
  const receipt = await processBatchIntents(batchIntents, batchType, timestamp);

  // Verify each intent was stored
  if (receipt && receipt.status === 1) {
    console.log("\n" + "-".repeat(70));
    console.log("  Verification");
    console.log("-".repeat(70));
    for (const intent of batchIntents) {
      await verifyIntent(intent.intentId);
    }
  }

  console.log("\n" + "=".repeat(70));
  console.log("  DONE");
  console.log("=".repeat(70) + "\n");
}

main().catch((err) => {
  console.error("\n  Script failed:", err.message);
  process.exit(1);
});
