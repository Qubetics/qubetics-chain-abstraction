#!/usr/bin/env node

/**
 * Complete Solver Setup Script
 * ============================
 * Onboards solvers, validates them, and adds both EVM (TICS) and BTC liquidity.
 *
 * EIP-712 Signing Pattern:
 *   - Each solver's `privateKey` is used ONLY for signing EIP-712 messages.
 *     The signer's address becomes the solver's on-chain identity.
 *   - A separate `TX_SENDER_PK` (gas payer) sends the transactions on-chain.
 *     The contract recovers the solver identity from the EIP-712 signature,
 *     NOT from msg.sender. This allows a single funded wallet to pay gas for
 *     all solvers without needing to fund each solver key.
 *
 * IMPORTANT: Each solver MUST use a different private key for EIP-712 signing.
 *
 * Usage:
 *   node setup_solver.js
 *
 * Required .env variables (loaded from project root ../../.env):
 *   SOLVER_CONTRACT_RPC_URL   - Qubetics RPC endpoint
 *   SOLVER_CONTRACT_ADDRESS   - SolverManager contract address
 *   TX_SENDER_PK              - Private key for the gas-paying wallet (sends all txs)
 *                                If not set, falls back to each solver's own key.
 *
 * Configure solvers in the SOLVERS array below. Each entry needs its own privateKey.
 */

import dotenv from 'dotenv';
import { ethers } from 'ethers';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load .env from project root (two levels up)
dotenv.config({ path: join(__dirname, '../../.env') });

// ============================================================
// SOLVERS CONFIG — each solver has its own private key for EIP-712 signing.
// The EIP-712 signer address is the solver's on-chain identity.
// TX_SENDER_PK from .env is used to pay gas and send transactions.
// ============================================================
const SOLVERS = [
  {
    // Solver 1
    privateKey: "a5d6d05532a0f6ee1de3586a2da787429a8b62289d776ca084783c8dc9ffa5a7",
    solverId: "12D3KooWJX7Gxkfp7UviibMhfi8VMVFyGpYAgFJm2LBqR3tJ2y9P",
    solverName: "Solver_1",
    chainIds: [0, 9029],
    solverAddresses: [
      "tb1q5h7k9m2n4p6r8t0v2x4z6y8w0u3s5q7l9c2d4f",   // BTC address
      "0xaB5d121c8c20DE97FF577DeE75aaA62a4F3bf93C",      // EVM address
    ],
    evmLiquidityAmount: "10000000000000000000",  // 10 TICS in wei
    btcLiquidityAmount: "10000",               // in satoshis
  },
  // {
  //   // Solver 2 — use a DIFFERENT private key
  //   privateKey: "15d5488130680e229fb5edceadec7c9a58b6236b5b5c08e339f89236f3ef59b2",
  //   solverId: "",
  //   solverName: "Solver_2",
  //   chainIds: [0, 9029],
  //   solverAddresses: [
  //     "tb1q8v9u5r6k3m4n2p0x7z9y8w6v5u4t3s2r1q0xyz",     // BTC address
  //     "0xd3C9D5DC51eb2bf66921533Ff664500a3042ff02",       // EVM address
  //   ],
  //   evmLiquidityAmount: "10000000000000000000",
  //   btcLiquidityAmount: "10000",
  // },
  // {
  //   // Solver 3 — use a DIFFERENT private key
  //   privateKey: "4289ba4c078eb7c639b72f3b253e03fe6420d64a3e2f60b2a6f6046b9e6d5010",
  //   solverId: "",
  //   solverName: "Solver_3",
  //   chainIds: [0, 9029],
  //   solverAddresses: [
  //     "tb1q2w3e4r5t6y7u8i9o0pqlkjhgfdsazxcvbnm123",
  //     "0x93F3D30c1c76652B964f63e547f1Fb6dA920a935",
  //   ],
  //   evmLiquidityAmount: "10000000000000000000",
  //   btcLiquidityAmount: "10000",
  // },
];

// ============================================================
// CONTRACT SETUP
// ============================================================
const RPC_URL = process.env.SOLVER_CONTRACT_RPC_URL || process.env.RPC_URL;
const CONTRACT_ADDRESS = process.env.SOLVER_CONTRACT_ADDRESS || process.env.SOLVER_MANAGER_ADDRESS;

const TX_SENDER_PK = process.env.TX_SENDER_PK;

if (!RPC_URL || !CONTRACT_ADDRESS) {
  console.error("SOLVER_CONTRACT_RPC_URL and SOLVER_CONTRACT_ADDRESS must be set in .env");
  process.exit(1);
}

const provider = new ethers.providers.JsonRpcProvider(RPC_URL);

// Gas payer wallet — sends all transactions. If TX_SENDER_PK is not set, we fall back
// to using each solver's own key (created per-solver in main loop).
const txSender = TX_SENDER_PK ? new ethers.Wallet(TX_SENDER_PK, provider) : null;

const ABI = [
  "function getNonce(address) view returns (uint256)",
  "function onboardSolver(string,string,uint256[],string[],uint256,bytes)",
  "function addLiquidityBatch(tuple(string solverId, uint256 amount, uint8 chainType)[])",
  "function validateSolverId(uint256,bytes)",
  "function isSolverActive(string) view returns (bool)",
  "function isSolverIdValidated(address) view returns (bool)",
  "function isSolverOnboarded(string) view returns (bool)",
  "function getSolverChainAmount(string,uint256) view returns (uint256)",
  "function getSolver(string) view returns (tuple(string,string,uint256[],string[],bool,bool,uint256,uint256))",
  "function MPC_ROLE() view returns (bytes32)",
  "function hasRole(bytes32,address) view returns (bool)",
  "function grantRole(bytes32,address)",
];

const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, provider);

// ============================================================
// HELPERS
// ============================================================

function formatAmount(amount, label) {
  const bn = ethers.BigNumber.from(amount);
  if (label === 'TICS') {
    return `${ethers.utils.formatEther(bn)} TICS`;
  }
  const btcStr = (Number(bn.toString()) / 1e8).toFixed(8);
  return `${btcStr} BTC (${bn.toString()} sats)`;
}

async function getEip712Domain() {
  const network = await provider.getNetwork();
  return {
    name: "SolverManager",
    version: "1",
    chainId: Number(network.chainId),
    verifyingContract: CONTRACT_ADDRESS,
  };
}

// ============================================================
// CHECK STATUS
// ============================================================
async function checkStatus(solverId) {
  try {
    const isOnboarded = await contract.isSolverOnboarded(solverId);
    const isActive = await contract.isSolverActive(solverId);

    console.log(`    Onboarded:   ${isOnboarded}`);
    console.log(`    Active:      ${isActive}`);

    if (isOnboarded) {
      const info = await contract.getSolver(solverId);
      console.log(`    Name:        ${info[1]}`);
      console.log(`    Validated:   ${info[5]}`);

      for (const chainId of info[2]) {
        const amount = await contract.getSolverChainAmount(solverId, chainId);
        const label = chainId.toString() === '0' ? 'BTC' : 'TICS';
        console.log(`    Liquidity (chain ${chainId}): ${formatAmount(amount, label)}`);
      }
    }

    return { isOnboarded, isActive };
  } catch (e) {
    console.log(`    Status: Not found (${e.message})`);
    return { isOnboarded: false, isActive: false };
  }
}

// ============================================================
// ONBOARD — EIP-712 signed by solver key, tx sent by gas payer
// The contract recovers the solver identity from the signature.
// ============================================================
async function onboard(signerWallet, senderWallet, config) {
  const isOnboarded = await contract.isSolverOnboarded(config.solverId);
  if (isOnboarded) {
    console.log("    Already onboarded — skipping.");
    return true;
  }

  const domain = await getEip712Domain();
  // Nonce is for the EIP-712 signer (solver identity), not the tx sender
  const nonce = await contract.getNonce(signerWallet.address);
  const deadline = Math.floor(Date.now() / 1000) + 3600;

  console.log(`    EIP-712 signer: ${signerWallet.address} (solver identity on-chain)`);
  console.log(`    Tx sender:      ${senderWallet.address} (gas payer)`);
  console.log(`    Nonce:          ${nonce.toString()}`);

  const types = {
    OnboardSolver: [
      { name: "solverId", type: "string" },
      { name: "solverName", type: "string" },
      { name: "chainIds", type: "uint256[]" },
      { name: "solverAddresses", type: "string[]" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
    ],
  };

  const message = {
    solverId: config.solverId,
    solverName: config.solverName,
    chainIds: config.chainIds,
    solverAddresses: config.solverAddresses,
    nonce,
    deadline,
  };

  // Solver key signs the EIP-712 message (determines on-chain identity)
  const signature = await signerWallet._signTypedData(domain, types, message);

  // Gas payer sends the transaction
  console.log("    Sending onboard tx...");
  const contractWithSender = contract.connect(senderWallet);
  const tx = await contractWithSender.onboardSolver(
    config.solverId,
    config.solverName,
    config.chainIds,
    config.solverAddresses,
    deadline,
    signature
  );

  console.log(`    Tx: ${tx.hash}`);
  const receipt = await tx.wait();
  console.log(`    Confirmed block ${receipt.blockNumber} (gas: ${receipt.gasUsed.toString()})`);
  return true;
}

// ============================================================
// VALIDATE — EIP-712 signed by solver key, tx sent by gas payer
// ============================================================
async function validate(signerWallet, senderWallet, solverId) {
  const isActive = await contract.isSolverActive(solverId);
  if (isActive) {
    console.log("    Already validated and active — skipping.");
    return true;
  }

  const domain = await getEip712Domain();
  // Nonce is for the EIP-712 signer (solver identity)
  const nonce = await contract.getNonce(signerWallet.address);
  const deadline = Math.floor(Date.now() / 1000) + 3600;

  console.log(`    EIP-712 signer: ${signerWallet.address} (solver identity)`);
  console.log(`    Tx sender:      ${senderWallet.address} (gas payer)`);
  console.log(`    Nonce:          ${nonce.toString()}`);

  const types = {
    ValidateSolver: [
      { name: "solverId", type: "string" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
    ],
  };

  const message = { solverId, nonce, deadline };

  // Solver key signs the EIP-712 message
  const signature = await signerWallet._signTypedData(domain, types, message);

  // Gas payer sends the transaction
  console.log("    Sending validate tx...");
  const contractWithSender = contract.connect(senderWallet);
  const tx = await contractWithSender.validateSolverId(deadline, signature);

  console.log(`    Tx: ${tx.hash}`);
  const receipt = await tx.wait();
  console.log(`    Confirmed block ${receipt.blockNumber} (gas: ${receipt.gasUsed.toString()})`);
  return true;
}

// ============================================================
// ADD LIQUIDITY — one tx per chain type (TICS first, then BTC)
// Sent by gas payer (needs MPC_ROLE on the sender address)
// ============================================================
async function addLiquidity(senderWallet, config) {
  const contractWithSender = contract.connect(senderWallet);

  // 1. Add TICS liquidity
  if (config.evmLiquidityAmount && config.evmLiquidityAmount !== "0") {
    console.log(`    [TICS] ${formatAmount(config.evmLiquidityAmount, 'TICS')}`);
    console.log(`    [TICS] Sending addLiquidityBatch...`);

    const tx = await contractWithSender.addLiquidityBatch([{
      solverId: config.solverId,
      amount: config.evmLiquidityAmount,
      chainType: 1,  // 1 = EVM/TICS
    }]);

    console.log(`    [TICS] Tx: ${tx.hash}`);
    const receipt = await tx.wait();
    console.log(`    [TICS] Confirmed block ${receipt.blockNumber} (gas: ${receipt.gasUsed.toString()})`);

    const updated = await contract.getSolverChainAmount(config.solverId, 9029);
    console.log(`    [TICS] Updated balance: ${formatAmount(updated, 'TICS')}`);
  } else {
    console.log("    [TICS] No amount configured — skipping.");
  }

  // 2. Add BTC liquidity
  if (config.btcLiquidityAmount && config.btcLiquidityAmount !== "0") {
    console.log(`    [BTC]  ${formatAmount(config.btcLiquidityAmount, 'BTC')}`);
    console.log(`    [BTC]  Sending addLiquidityBatch...`);

    const tx = await contractWithSender.addLiquidityBatch([{
      solverId: config.solverId,
      amount: config.btcLiquidityAmount,
      chainType: 0,  // 0 = BTC
    }]);

    console.log(`    [BTC]  Tx: ${tx.hash}`);
    const receipt = await tx.wait();
    console.log(`    [BTC]  Confirmed block ${receipt.blockNumber} (gas: ${receipt.gasUsed.toString()})`);

    const updated = await contract.getSolverChainAmount(config.solverId, 0);
    console.log(`    [BTC]  Updated balance: ${formatAmount(updated, 'BTC')}`);
  } else {
    console.log("    [BTC]  No amount configured — skipping.");
  }

  return true;
}

// ============================================================
// MAIN — processes each solver sequentially
// ============================================================
async function main() {
  const network = await provider.getNetwork();

  console.log("\n" + "=".repeat(60));
  console.log("  Solver Setup Script");
  console.log("=".repeat(60));
  console.log(`  RPC:         ${RPC_URL}`);
  console.log(`  Chain ID:    ${network.chainId}`);
  console.log(`  Contract:    ${CONTRACT_ADDRESS}`);
  console.log(`  Solvers:     ${SOLVERS.length}`);
  console.log("=".repeat(60));

  // Validate that all solver private keys are unique
  const seenKeys = new Set();
  for (const solver of SOLVERS) {
    const normalized = solver.privateKey.replace(/^0x/, '').toLowerCase();
    if (seenKeys.has(normalized)) {
      console.error(`\nERROR: Duplicate private key found for solver "${solver.solverId}".`);
      console.error("Each solver MUST have a unique private key (the signer = on-chain identity).");
      process.exit(1);
    }
    seenKeys.add(normalized);
  }

  if (txSender) {
    console.log(`  Tx Sender:   ${txSender.address} (gas payer for all txs)`);
  } else {
    console.log(`  Tx Sender:   (using each solver's own key — set TX_SENDER_PK to separate)`);
  }

  for (let i = 0; i < SOLVERS.length; i++) {
    const config = SOLVERS[i];
    // EIP-712 signer — determines solver's on-chain identity
    const signerWallet = new ethers.Wallet(config.privateKey, provider);
    // Gas payer — sends transactions. Falls back to solver key if TX_SENDER_PK not set.
    const senderWallet = txSender || signerWallet;

    console.log(`\n${"#".repeat(60)}`);
    console.log(`  SOLVER ${i + 1}/${SOLVERS.length}: ${config.solverId}`);
    console.log(`  EIP-712 Signer: ${signerWallet.address} (solver identity)`);
    console.log(`  Tx Sender:      ${senderWallet.address} (gas payer)`);
    console.log(`${"#".repeat(60)}`);

    // Step 0: Check current status
    console.log(`\n  [Status]`);
    await checkStatus(config.solverId);

    // Step 1: Onboard (EIP-712 signed by solver key, tx sent by gas payer)
    console.log(`\n  [Onboard]`);
    try {
      await onboard(signerWallet, senderWallet, config);
    } catch (e) {
      console.error(`    ERROR: ${e.message}`);
      if (e.error?.data) console.error(`    Revert: ${e.error.data}`);
      continue;
    }

    // Step 2: Validate (EIP-712 signed by solver key, tx sent by gas payer)
    console.log(`\n  [Validate]`);
    try {
      await validate(signerWallet, senderWallet, config.solverId);
    } catch (e) {
      console.error(`    ERROR: ${e.message}`);
      if (e.error?.data) console.error(`    Revert: ${e.error.data}`);
      continue;
    }

    // Step 3: Add liquidity (sent by gas payer — needs MPC_ROLE on sender address)
    console.log(`\n  [Add Liquidity]`);
    try {
      await addLiquidity(senderWallet, config);
    } catch (e) {
      console.error(`    ERROR: ${e.message}`);
      if (e.error?.data) console.error(`    Revert: ${e.error.data}`);
      continue;
    }

    // Final status
    console.log(`\n  [Final Status]`);
    await checkStatus(config.solverId);
  }

  console.log(`\n${"=".repeat(60)}`);
  console.log(`  ALL DONE — ${SOLVERS.length} solver(s) processed`);
  console.log(`${"=".repeat(60)}\n`);
}

main().catch((err) => {
  console.error("\nFatal error:", err.message || err);
  if (err.error?.data) console.error("Revert data:", err.error.data);
  process.exit(1);
});
