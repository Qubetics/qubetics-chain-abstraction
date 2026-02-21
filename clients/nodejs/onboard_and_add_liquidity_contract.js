#!/usr/bin/env node

/**
 * Onboard a solver and/or add liquidity directly on the SolverManager contract (on-chain).
 * Uses SOLVER_CONTRACT_RPC_URL, SOLVER_CONTRACT_ADDRESS, SOLVER_CONTRACT_CHAIN_ID from env.
 *
 * Usage:
 *   # Onboard only (validator signs EIP-712 and submits tx)
 *   # Option A: Provide SOLVER_ADDRESSES explicitly
 *   VALIDATOR_PRIVATE_KEY=0x... SOLVER_ID=mySolver SOLVER_NAME="My Solver" \
 *     CHAIN_IDS=0,9029 SOLVER_ADDRESSES=bc1q...,0x... node onboard_and_add_liquidity_contract.js onboard
 *
 *   # Option B: Derive ETH address from new solver's private key (set BTC_ADDRESS separately)
 *   VALIDATOR_PRIVATE_KEY=0x<admin_key> SOLVER_PRIVATE_KEY=0x<new_solver_key> \
 *     SOLVER_ID=mySolver SOLVER_NAME="My Solver" BTC_ADDRESS=tb1q... \
 *     node onboard_and_add_liquidity_contract.js onboard
 *
 *   # Add liquidity only (caller must have MPC_ROLE)
 *   MPC_PRIVATE_KEY=0x... SOLVER_ID=mySolver AMOUNT=1000000000000000000 CHAIN_TYPE=1 \
 *     node onboard_and_add_liquidity_contract.js add
 *
 *   # Both: onboard then add liquidity
 *   VALIDATOR_PRIVATE_KEY=0x... MPC_PRIVATE_KEY=0x... SOLVER_ID=... SOLVER_NAME=... \
 *     CHAIN_IDS=0,9029 SOLVER_ADDRESSES=... AMOUNT=... CHAIN_TYPE=1 \
 *     node onboard_and_add_liquidity_contract.js both
 *
 * Env:
 *   SOLVER_CONTRACT_RPC_URL, SOLVER_CONTRACT_ADDRESS, SOLVER_CONTRACT_CHAIN_ID
 *   VALIDATOR_PRIVATE_KEY - for onboarding (must be validatorAddress on contract, signs EIP-712 & submits tx)
 *   SOLVER_PRIVATE_KEY - (optional) new solver's private key; ETH address derived from this
 *   MPC_PRIVATE_KEY - for addLiquidityBatch (must have MPC_ROLE)
 *   SOLVER_ID, SOLVER_NAME - for onboarding
 *   CHAIN_IDS - comma-separated (e.g. 0,9029 for BTC, TICS). Default: 0,9029 when using SOLVER_PRIVATE_KEY
 *   SOLVER_ADDRESSES - comma-separated, same order as chainIds (e.g. btcAddr,ethAddr)
 *   BTC_ADDRESS - BTC address for new solver (used when SOLVER_PRIVATE_KEY is set)
 *   AMOUNT - wei/sats string for add liquidity
 *   CHAIN_TYPE - 0 = BTC, 1 = TICS (SolverManager.ChainType)
 */

import { ethers } from 'ethers';

const SOLVER_MANAGER_ABI = [
  'function onboardSolver(string solverId, string solverName, uint256[] chainIds, string[] solverAddresses, uint256 deadline, bytes signature)',
  'function addLiquidityBatch(tuple(string solverId, uint256 amount, uint8 chainType, string txId)[] deposits)',
  'function removeLiquidity(tuple(string solverId, uint256 amount, uint8 chainType, string transactionHash)[] requests)',
  'function getDomainSeparator() view returns (bytes32)',
  'function getSolverId(address solver) view returns (string)',
  'function getMinimumLiquidityTICS() view returns (uint256)',
  'function getMinimumLiquidityBTC() view returns (uint256)',
  'function eip712Domain() view returns (bytes1 fields, string name, string version, uint256 chainId, address verifyingContract, bytes32 salt, uint256[] extensions)',
  'function getOnboardNonce(address) view returns (uint256)',
];

const colors = {
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  reset: '\x1b[0m',
};

function getEnv(name, def) {
  const v = process.env[name];
  if (v !== undefined && v !== '') return v;
  return def;
}

async function getEip712Domain(contract) {
  try {
    const d = await contract.eip712Domain();
    return {
      name: d.name,
      version: d.version,
      chainId: d.chainId.toNumber ? d.chainId.toNumber() : Number(d.chainId),
      verifyingContract: d.verifyingContract,
    };
  } catch (e) {
    console.warn(`${colors.yellow}Could not read eip712Domain from contract, using defaults: ${e.message}${colors.reset}`);
    const network = await contract.provider.getNetwork();
    const chainId = network.chainId;
    return {
      name: 'SolverManager',
      version: '1',
      chainId: chainId.toNumber ? chainId.toNumber() : Number(chainId),
      verifyingContract: contract.address,
    };
  }
}

/**
 * EIP-712 typed data for OnboardSolver.
 * Struct must match contract's ONBOARD_SOLVER_TYPEHASH.
 */
function buildOnboardTypedData(domain, solverId, solverName, chainIds, solverAddresses, nonce, deadline) {
  return {
    types: {
      OnboardSolver: [
        { name: 'solverId', type: 'string' },
        { name: 'solverName', type: 'string' },
        { name: 'chainIds', type: 'uint256[]' },
        { name: 'solverAddresses', type: 'string[]' },
        { name: 'nonce', type: 'uint256' },
        { name: 'deadline', type: 'uint256' },
      ],
    },
    primaryType: 'OnboardSolver',
    domain,
    message: {
      solverId,
      solverName,
      chainIds: chainIds.map(n => ethers.BigNumber.from(n)),
      solverAddresses,
      nonce: ethers.BigNumber.from(nonce),
      deadline: ethers.BigNumber.from(deadline),
    },
  };
}

async function runOnboard(provider, contract, wallet) {
  const solverId = getEnv('SOLVER_ID', '');
  const solverName = getEnv('SOLVER_NAME', 'Solver');
  const solverPrivateKey = getEnv('SOLVER_PRIVATE_KEY', '');
  const btcAddress = getEnv('BTC_ADDRESS', '');
  let chainIdsStr = getEnv('CHAIN_IDS', '');
  let addressesStr = getEnv('SOLVER_ADDRESSES', '');

  if (!solverId) {
    throw new Error('SOLVER_ID is required for onboard');
  }

  // If SOLVER_PRIVATE_KEY is provided, derive the ETH address from it
  if (solverPrivateKey) {
    const solverWallet = new ethers.Wallet(solverPrivateKey);
    const derivedEthAddress = solverWallet.address;
    console.log(`${colors.blue}Derived ETH address from SOLVER_PRIVATE_KEY: ${derivedEthAddress}${colors.reset}`);

    if (!btcAddress) {
      throw new Error('BTC_ADDRESS is required when using SOLVER_PRIVATE_KEY');
    }

    // Default to both BTC (0) and EVM (9029) chains
    if (!chainIdsStr) {
      chainIdsStr = '0,9029';
    }
    // Build solver addresses: BTC first, then ETH
    addressesStr = `${btcAddress},${derivedEthAddress}`;
    console.log(`${colors.blue}Using addresses: BTC=${btcAddress}, ETH=${derivedEthAddress}${colors.reset}`);
  }

  if (!chainIdsStr) {
    chainIdsStr = '9029'; // Default if nothing specified
  }

  const chainIds = chainIdsStr.split(',').map(s => parseInt(s.trim(), 10));
  const solverAddresses = addressesStr.split(',').map(s => s.trim()).filter(Boolean);
  if (solverAddresses.length !== chainIds.length) {
    throw new Error('SOLVER_ADDRESSES length must match CHAIN_IDS length');
  }

  const deadline = Math.floor(Date.now() / 1000) + 3600; // 1 hour

  // Get the nonce for the validator wallet
  const nonce = await contract.getOnboardNonce(wallet.address);
  console.log(`${colors.blue}Validator onboard nonce: ${nonce.toString()}${colors.reset}`);

  const domain = await getEip712Domain(contract);
  const typedData = buildOnboardTypedData(domain, solverId, solverName, chainIds, solverAddresses, nonce, deadline);

  const signature = await wallet._signTypedData(
    typedData.domain,
    { OnboardSolver: typedData.types.OnboardSolver },
    typedData.message
  );

  console.log(`${colors.blue}Onboarding solver ${solverId}...${colors.reset}`);
  console.log(`${colors.blue}  Solver Name: ${solverName}${colors.reset}`);
  console.log(`${colors.blue}  Chain IDs: ${chainIds.join(', ')}${colors.reset}`);
  console.log(`${colors.blue}  Solver Addresses: ${solverAddresses.join(', ')}${colors.reset}`);
  console.log(`${colors.blue}  Validator/Admin signing & submitting: ${wallet.address}${colors.reset}`);
  const tx = await contract.onboardSolver(
    solverId,
    solverName,
    chainIds,
    solverAddresses,
    deadline,
    signature
  );
  const receipt = await tx.wait();
  console.log(`${colors.green}✅ OnboardSolver tx: ${receipt.transactionHash}${colors.reset}`);
  return receipt;
}

async function runAddLiquidity(contract, wallet) {
  const solverId = getEnv('SOLVER_ID', '');
  const amountStr = getEnv('AMOUNT', '1000000000000000000');
  const chainType = parseInt(getEnv('CHAIN_TYPE', '1'), 10); // 0 = BTC, 1 = TICS
  if (!solverId) {
    throw new Error('SOLVER_ID is required for add');
  }
  const amount = ethers.BigNumber.from(amountStr);

  const txId = getEnv('TX_ID', '');
  const deposits = [{ solverId, amount, chainType, txId }];
  console.log(`${colors.blue}Calling addLiquidityBatch: solverId=${solverId}, amount=${amountStr}, chainType=${chainType}, txId=${txId}${colors.reset}`);
  const tx = await contract.addLiquidityBatch(deposits);
  const receipt = await tx.wait();
  console.log(`${colors.green}✅ addLiquidityBatch tx: ${receipt.transactionHash}${colors.reset}`);
  return receipt;
}

async function runRemoveLiquidity(contract, wallet) {
  const solverId = getEnv('SOLVER_ID', '');
  const amountStr = getEnv('AMOUNT', '1000000000000000000');
  const chainType = parseInt(getEnv('CHAIN_TYPE', '1'), 10); // 0 = BTC, 1 = TICS
  const txHash = getEnv('TX_HASH', '0x0000000000000000000000000000000000000000000000000000000000000000');
  if (!solverId) {
    throw new Error('SOLVER_ID is required for remove');
  }
  const amount = ethers.BigNumber.from(amountStr);

  const requests = [{ solverId, amount, chainType, transactionHash: txHash }];
  console.log(`${colors.blue}Calling removeLiquidity: solverId=${solverId}, amount=${amountStr}, chainType=${chainType}, txHash=${txHash}${colors.reset}`);
  const tx = await contract.removeLiquidity(requests);
  const receipt = await tx.wait();
  console.log(`${colors.green}✅ removeLiquidity tx: ${receipt.transactionHash}${colors.reset}`);
  return receipt;
}

async function main() {
  const rpcUrl = getEnv('SOLVER_CONTRACT_RPC_URL', 'http://127.0.0.1:8545');
  const contractAddress = getEnv('SOLVER_CONTRACT_ADDRESS', '');
  const chainId = getEnv('SOLVER_CONTRACT_CHAIN_ID', '9029');

  if (!contractAddress) {
    console.error(`${colors.red}SOLVER_CONTRACT_ADDRESS is required${colors.reset}`);
    process.exit(1);
  }

  const provider = new ethers.providers.JsonRpcProvider(rpcUrl);
  const contract = new ethers.Contract(contractAddress, SOLVER_MANAGER_ABI, provider);

  const cmd = (process.argv[2] || 'both').toLowerCase();

  if (cmd === 'onboard') {
    const pk = getEnv('VALIDATOR_PRIVATE_KEY', '');
    if (!pk) {
      console.error(`${colors.red}VALIDATOR_PRIVATE_KEY is required for onboard${colors.reset}`);
      process.exit(1);
    }
    const wallet = new ethers.Wallet(pk, provider);
    const signerContract = contract.connect(wallet);
    await runOnboard(provider, signerContract, wallet);
    return;
  }

  if (cmd === 'add') {
    const pk = getEnv('MPC_PRIVATE_KEY', getEnv('VALIDATOR_PRIVATE_KEY', ''));
    if (!pk) {
      console.error(`${colors.red}MPC_PRIVATE_KEY is required for add (wallet must have MPC_ROLE)${colors.reset}`);
      process.exit(1);
    }
    const wallet = new ethers.Wallet(pk, provider);
    const signerContract = contract.connect(wallet);
    await runAddLiquidity(signerContract, wallet);
    return;
  }

  if (cmd === 'both') {
    const validatorPk = getEnv('VALIDATOR_PRIVATE_KEY', '');
    const mpcPk = getEnv('MPC_PRIVATE_KEY', validatorPk);
    if (!validatorPk) {
      console.error(`${colors.red}VALIDATOR_PRIVATE_KEY is required for both${colors.reset}`);
      process.exit(1);
    }
    const validatorWallet = new ethers.Wallet(validatorPk, provider);
    await runOnboard(provider, contract, validatorWallet);
    const mpcWallet = new ethers.Wallet(mpcPk, provider);
    const signerContract = contract.connect(mpcWallet);
    await runAddLiquidity(signerContract, mpcWallet);
    return;
  }

  if (cmd === 'remove') {
    const pk = getEnv('MPC_PRIVATE_KEY', getEnv('VALIDATOR_PRIVATE_KEY', ''));
    if (!pk) {
      console.error(`${colors.red}MPC_PRIVATE_KEY is required for remove (wallet must have MPC_ROLE)${colors.reset}`);
      process.exit(1);
    }
    const wallet = new ethers.Wallet(pk, provider);
    const signerContract = contract.connect(wallet);
    await runRemoveLiquidity(signerContract, wallet);
    return;
  }

  console.error(`${colors.red}Unknown command: ${cmd}. Use onboard | add | remove | both${colors.reset}`);
  process.exit(1);
}

main().catch((err) => {
  console.error(`${colors.red}${err.message}${colors.reset}`);
  process.exit(1);
});
