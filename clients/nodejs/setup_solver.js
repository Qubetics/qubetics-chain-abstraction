#!/usr/bin/env node

/**
 * Complete Solver Setup Script
 * ============================
 * Onboards solvers, validates them, and adds both EVM (TICS) and BTC liquidity.
 *
 * How the contract works:
 *   - The `validatorAddress` (stored on-chain) signs EIP-712 messages to authorize
 *     onboarding and validation. This is a "permission slip" from the validator.
 *   - Each solver sends the transaction themselves (msg.sender). The contract maps
 *     msg.sender as the solver's on-chain EVM identity. One address = one solver.
 *   - addLiquidityBatch has no msg.sender restriction, so anyone can call it.
 *
 * Required .env variables (loaded from project root ../../.env):
 *   SOLVER_CONTRACT_RPC_URL   - Qubetics RPC endpoint
 *   SOLVER_CONTRACT_ADDRESS   - SolverManager contract address
 *   VALIDATOR_PK              - Private key of the validator (signs EIP-712 messages)
 *
 * Configure solvers in the SOLVERS array below.
 * Each solver's `privateKey` is used to send transactions — msg.sender becomes the solver identity.
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
// SOLVERS CONFIG
// Each solver's privateKey is used to SEND transactions (msg.sender = solver identity).
// The validator key (from .env) signs EIP-712 messages to authorize actions.
// ============================================================
const SOLVERS = [
  {
    // Solver 1 — this key's address becomes the solver's on-chain identity
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
  //   // Solver 2 — use a DIFFERENT private key (different msg.sender = different solver)
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
const VALIDATOR_PK = process.env.VALIDATOR_PK;

if (!RPC_URL || !CONTRACT_ADDRESS) {
  console.error("SOLVER_CONTRACT_RPC_URL and SOLVER_CONTRACT_ADDRESS must be set in .env");
  process.exit(1);
}

if (!VALIDATOR_PK) {
  console.error("VALIDATOR_PK must be set in .env (the validator's private key for EIP-712 signing)");
  process.exit(1);
}

const provider = new ethers.providers.JsonRpcProvider(RPC_URL);

// Validator wallet — signs EIP-712 messages (must match validatorAddress on contract)
const validatorWallet = new ethers.Wallet(VALIDATOR_PK, provider);

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
  "function validatorAddress() view returns (address)",
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
// ONBOARD
// - Validator signs EIP-712 message (authorization)
// - Solver sends the transaction (msg.sender = solver identity)
// ============================================================
async function onboard(solverWallet, config) {
  const isOnboarded = await contract.isSolverOnboarded(config.solverId);
  if (isOnboarded) {
    console.log("    Already onboarded — skipping.");
    return true;
  }

  const domain = await getEip712Domain();
  // Nonce is the validator's nonce (contract uses nonces[validatorAddress])
  const nonce = await contract.getNonce(validatorWallet.address);
  const deadline = Math.floor(Date.now() / 1000) + 3600;

  console.log(`    Validator (EIP-712 signer): ${validatorWallet.address}`);
  console.log(`    Solver (msg.sender):        ${solverWallet.address}`);
  console.log(`    Validator nonce:            ${nonce.toString()}`);

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

  // Validator signs the EIP-712 message (authorization)
  const signature = await validatorWallet._signTypedData(domain, types, message);

  // Solver sends the transaction (msg.sender becomes the solver identity)
  console.log("    Sending onboard tx...");
  const contractWithSolver = contract.connect(solverWallet);
  const tx = await contractWithSolver.onboardSolver(
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
// VALIDATE
// - Validator signs EIP-712 message (authorization)
// - Solver sends the transaction (msg.sender must match onboarded address)
// ============================================================
async function validate(solverWallet, solverId) {
  const isValidated = await contract.isSolverIdValidated(solverWallet.address);
  if (isValidated) {
    console.log("    Already validated — skipping.");
    return true;
  }

  const domain = await getEip712Domain();
  // Nonce is the validator's nonce (contract uses nonces[validatorAddress])
  const nonce = await contract.getNonce(validatorWallet.address);
  const deadline = Math.floor(Date.now() / 1000) + 3600;

  console.log(`    Validator (EIP-712 signer): ${validatorWallet.address}`);
  console.log(`    Solver (msg.sender):        ${solverWallet.address}`);
  console.log(`    Validator nonce:            ${nonce.toString()}`);

  const types = {
    ValidateSolver: [
      { name: "solverId", type: "string" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
    ],
  };

  const message = { solverId, nonce, deadline };

  // Validator signs the EIP-712 message (authorization)
  const signature = await validatorWallet._signTypedData(domain, types, message);

  // Solver sends the transaction (msg.sender must be the onboarded solver)
  console.log("    Sending validate tx...");
  const contractWithSolver = contract.connect(solverWallet);
  const tx = await contractWithSolver.validateSolverId(deadline, signature);

  console.log(`    Tx: ${tx.hash}`);
  const receipt = await tx.wait();
  console.log(`    Confirmed block ${receipt.blockNumber} (gas: ${receipt.gasUsed.toString()})`);
  return true;
}

// ============================================================
// ADD LIQUIDITY
// No msg.sender restriction — anyone can call. We use the solver wallet here.
// ============================================================
async function addLiquidity(solverWallet, config) {
  const contractWithSolver = contract.connect(solverWallet);

  // 1. Add TICS liquidity
  if (config.evmLiquidityAmount && config.evmLiquidityAmount !== "0") {
    console.log(`    [TICS] ${formatAmount(config.evmLiquidityAmount, 'TICS')}`);
    console.log(`    [TICS] Sending addLiquidityBatch...`);

    const tx = await contractWithSolver.addLiquidityBatch([{
      solverId: config.solverId,
      amount: config.evmLiquidityAmount,
      chainType: 1,  // 1 = TICS
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

    const tx = await contractWithSolver.addLiquidityBatch([{
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
  console.log(`  Validator:   ${validatorWallet.address} (EIP-712 signer)`);
  console.log("=".repeat(60));

  // Verify validator matches on-chain validatorAddress
  const onChainValidator = await contract.validatorAddress();
  if (onChainValidator.toLowerCase() !== validatorWallet.address.toLowerCase()) {
    console.error(`\nERROR: VALIDATOR_PK address (${validatorWallet.address}) does not match`);
    console.error(`       on-chain validatorAddress (${onChainValidator})`);
    console.error("       The contract will reject all signatures.");
    process.exit(1);
  }
  console.log(`  Validator verified against on-chain address.`);

  // Validate that all solver private keys are unique
  const seenKeys = new Set();
  for (const solver of SOLVERS) {
    const normalized = solver.privateKey.replace(/^0x/, '').toLowerCase();
    if (seenKeys.has(normalized)) {
      console.error(`\nERROR: Duplicate private key found for solver "${solver.solverId}".`);
      console.error("Each solver MUST have a unique private key (unique msg.sender = unique solver).");
      process.exit(1);
    }
    seenKeys.add(normalized);
  }

  for (let i = 0; i < SOLVERS.length; i++) {
    const config = SOLVERS[i];
    // Solver wallet — sends transactions. msg.sender = solver's on-chain identity.
    const solverWallet = new ethers.Wallet(config.privateKey, provider);

    console.log(`\n${"#".repeat(60)}`);
    console.log(`  SOLVER ${i + 1}/${SOLVERS.length}: ${config.solverId}`);
    console.log(`  Solver address (msg.sender): ${solverWallet.address}`);
    console.log(`${"#".repeat(60)}`);

    // Step 0: Check current status
    console.log(`\n  [Status]`);
    await checkStatus(config.solverId);

    // Step 1: Onboard (validator signs EIP-712, solver sends tx)
    console.log(`\n  [Onboard]`);
    try {
      await onboard(solverWallet, config);
    } catch (e) {
      console.error(`    ERROR: ${e.message}`);
      if (e.error?.data) console.error(`    Revert: ${e.error.data}`);
      continue;
    }

    // Step 2: Validate (validator signs EIP-712, solver sends tx)
    console.log(`\n  [Validate]`);
    try {
      await validate(solverWallet, config.solverId);
    } catch (e) {
      console.error(`    ERROR: ${e.message}`);
      if (e.error?.data) console.error(`    Revert: ${e.error.data}`);
      continue;
    }

    // Step 3: Add liquidity (solver sends tx, no special auth needed)
    console.log(`\n  [Add Liquidity]`);
    try {
      await addLiquidity(solverWallet, config);
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
