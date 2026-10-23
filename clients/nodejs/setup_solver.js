#!/usr/bin/env node

/**
 * Complete Solver Setup Script
 * ============================
 * Onboards solvers, validates them, and adds both EVM (TICS) and BTC liquidity.
 *
 * Usage:
 *   node setup_solver.js <PeerId1> <PeerId2> ... <PeerIdN>
 *
 * Example:
 *   node setup_solver.js 12D3KooWMU5HZBpd1pnzPsF6FkKXE8j42QGFJ2CyUpxRtf1HdQkM 12D3KooWMFWExBUizT3PgWEztcG9oYqQuc7MwXUXH7itqen53878
 *
 * For each PeerId, a random EVM private key is generated, and a BTC testnet
 * address is derived from it. No need to manually configure keys or addresses.
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
 */

import dotenv from 'dotenv';
import { ethers } from 'ethers';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import * as bitcoin from 'bitcoinjs-lib';
import * as tinysecp from 'tiny-secp256k1';
import { ECPairFactory } from 'ecpair';

const ECPair = ECPairFactory(tinysecp);

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load .env from project root (two levels up)
dotenv.config({ path: join(__dirname, '../../.env') });

// ============================================================
// PEER IDS — pass them as CLI arguments
// ============================================================
const PEER_IDS = process.argv.slice(2);

if (PEER_IDS.length === 0) {
  console.error("Usage: node setup_solver.js <PeerId1> [PeerId2] ... [PeerIdN]");
  console.error("Example: node setup_solver.js 12D3KooWMU5HZBpd1pnzPsF6FkKXE8j42QGFJ2CyUpxRtf1HdQkM");
  process.exit(1);
}

// ============================================================
// AUTO-GENERATE SOLVER CONFIGS
// For each PeerId, generate a random private key, derive EVM address,
// and derive a BTC testnet address from the same key.
// ============================================================
const TESTNET = bitcoin.networks.testnet;
const EVM_LIQUIDITY = "10000000000000000000"; // 10 TICS
const BTC_LIQUIDITY = "10000"; // 10000 sats

function generateSolverConfig(peerId, index) {
  const wallet = ethers.Wallet.createRandom();
  const privateKeyBytes = Buffer.from(wallet.privateKey.slice(2), 'hex');
  const keyPair = ECPair.fromPrivateKey(privateKeyBytes, { network: TESTNET });
  const { address: btcAddress } = bitcoin.payments.p2wpkh({
    pubkey: Buffer.from(keyPair.publicKey),
    network: TESTNET,
  });

  return {
    privateKey: wallet.privateKey,
    solverId: peerId,
    solverName: `Solver_${index + 1}`,
    chainIds: [0, 9029],
    solverAddresses: [btcAddress, wallet.address],
    evmLiquidityAmount: EVM_LIQUIDITY,
    btcLiquidityAmount: BTC_LIQUIDITY,
  };
}

const SOLVERS = PEER_IDS.map((peerId, i) => generateSolverConfig(peerId, i));


// ============================================================
// CONTRACT SETUP
// ============================================================
const RPC_URL = process.env.SOLVER_CONTRACT_RPC_URL || process.env.RPC_URL;
const CONTRACT_ADDRESS = process.env.SOLVER_CONTRACT_ADDRESS || process.env.SOLVER_MANAGER_ADDRESS;
const VALIDATOR_PK = process.env.VALIDATOR_PK;
const FUNDING_PK = process.env.FUNDING_PK;
const FUND_AMOUNT = "10";

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

// Funding wallet — sends TICS to solvers for gas (defaults to validator)
const fundingWallet = new ethers.Wallet(FUNDING_PK, provider);

const ABI = [
  "function getOnboardNonce(address) view returns (uint256)",
  "function getValidateNonce(address) view returns (uint256)",
  "function onboardSolver(string,string,uint256[],string[],uint256,bytes)",
  "function addLiquidityBatch(tuple(string solverId, uint256 amount, uint8 chainType, string txId)[])",
  "function validateSolverId(uint256,bytes)",
  "function isSolverActive(string) view returns (bool)",
  "function isSolverIdValidated(string) view returns (bool)",
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
  // Nonce is the validator's onboard nonce (contract uses onboardNonces[validatorAddress])
  const nonce = await contract.getOnboardNonce(validatorWallet.address);
  const deadline = Math.floor(Date.now() / 1000) + 3600;

  console.log(`    Validator (EIP-712 signer): ${validatorWallet.address}`);
  console.log(`    Solver (msg.sender):        ${solverWallet.address}`);
  console.log(`    Validator onboard nonce:    ${nonce.toString()}`);

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
  const isValidated = await contract.isSolverIdValidated(solverId);
  if (isValidated) {
    console.log("    Already validated — skipping.");
    return true;
  }

  const domain = await getEip712Domain();
  // Nonce is the validator's validate nonce (contract uses validateNonces[validatorAddress])
  const nonce = await contract.getValidateNonce(validatorWallet.address);
  const deadline = Math.floor(Date.now() / 1000) + 3600;

  console.log(`    Validator (EIP-712 signer): ${validatorWallet.address}`);
  console.log(`    Solver (msg.sender):        ${solverWallet.address}`);
  console.log(`    Validator validate nonce:   ${nonce.toString()}`);

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
      txId: '',
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
      txId: '',
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
// FUNDING
// - Sent from fundingWallet (defaults to validator)
// - Ensures solver has enough TICS for gas and liquidity deposit
// ============================================================
async function fundSolver(solverAddress, amountTics) {
  const balance = await provider.getBalance(solverAddress);
  const required = ethers.utils.parseEther(amountTics);

  if (balance.lt(required)) {
    const toFund = required.sub(balance);
    console.log(`    Funding ${solverAddress} with ${ethers.utils.formatEther(toFund)} TICS...`);

    const tx = await fundingWallet.sendTransaction({
      to: solverAddress,
      value: toFund,
    });

    console.log(`    Tx: ${tx.hash}`);
    await tx.wait();
    console.log(`    Funding confirmed.`);
  } else {
    console.log(`    Balance looks sufficient (${ethers.utils.formatEther(balance)} TICS).`);
  }
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

  // Print generated solver details
  console.log("\n  Generated Solver Configs:");
  for (const s of SOLVERS) {
    const w = new ethers.Wallet(s.privateKey);
    console.log(`    ${s.solverName} (${s.solverId.slice(0, 20)}...)`);
    console.log(`      EVM:  ${w.address}`);
    console.log(`      BTC:  ${s.solverAddresses[0]}`);
    console.log(`      Key:  ${s.privateKey}`);
  }
  console.log("");

  // Verify validator matches on-chain validatorAddress
  const onChainValidator = await contract.validatorAddress();
  if (onChainValidator.toLowerCase() !== validatorWallet.address.toLowerCase()) {
    console.error(`\nERROR: VALIDATOR_PK address (${validatorWallet.address}) does not match`);
    console.error(`       on-chain validatorAddress (${onChainValidator})`);
    console.error("       The contract will reject all signatures.");
    process.exit(1);
  }
  console.log(`  Validator verified against on-chain address.`);

  for (let i = 0; i < SOLVERS.length; i++) {
    const config = SOLVERS[i];
    // Solver wallet — sends transactions. msg.sender = solver's on-chain identity.
    const solverWallet = new ethers.Wallet(config.privateKey, provider);

    console.log(`\n${"#".repeat(60)}`);
    console.log(`  SOLVER ${i + 1}/${SOLVERS.length}: ${config.solverId}`);
    console.log(`  Solver address (msg.sender): ${solverWallet.address}`);
    console.log(`  BTC address:                 ${config.solverAddresses[0]}`);
    console.log(`${"#".repeat(60)}`);

    // Step -1: Fund solver if needed
    console.log(`\n  [Funding]`);
    try {
      await fundSolver(solverWallet.address, FUND_AMOUNT);
    } catch (e) {
      console.error(`    ERROR during funding: ${e.message}`);
      // Continue even if funding fails, as balance might already be enough
    }

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
