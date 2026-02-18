#!/usr/bin/env node

/**
 * Check if a solver address is validated on the SolverManager contract.
 * Usage:
 *   node check_solver_validated.js <solver_evm_address>
 *   SOLVER_ADDRESS=0x... node check_solver_validated.js
 *
 * Requires in .env (or env):
 *   SOLVER_CONTRACT_RPC_URL or RPC_URL
 *   SOLVER_MANAGER_CONTRACT_ADDRESS or SOLVER_MANAGER_ADDRESS (contract address)
 */

import dotenv from 'dotenv';
import { ethers } from 'ethers';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

dotenv.config({ path: join(__dirname, '../../.env') });

const RPC_URL = process.env.SOLVER_CONTRACT_RPC_URL || process.env.RPC_URL;
const CONTRACT_ADDRESS =
  process.env.SOLVER_MANAGER_CONTRACT_ADDRESS || process.env.SOLVER_MANAGER_ADDRESS;
const SOLVER_ADDRESS = process.env.SOLVER_ADDRESS || process.argv[2];

const ABI = [
  'function isSolverIdValidated(address) view returns (bool)',
  'function getSolverEvmAddress(string) view returns (address)',
  'function getSolverId(address) view returns (string)',
];

function usage() {
  console.error(`
Usage:
  node check_solver_validated.js <solver_evm_address>
  SOLVER_ADDRESS=0x... node check_solver_validated.js

Env:
  SOLVER_CONTRACT_RPC_URL or RPC_URL
  SOLVER_MANAGER_CONTRACT_ADDRESS or SOLVER_MANAGER_ADDRESS (solver contract address)
  SOLVER_ADDRESS (optional, overrides positional arg)
`);
}

async function main() {
  if (!RPC_URL) {
    console.error('❌ Set SOLVER_CONTRACT_RPC_URL or RPC_URL in .env');
    usage();
    process.exit(1);
  }
  if (!CONTRACT_ADDRESS || !CONTRACT_ADDRESS.startsWith('0x')) {
    console.error('❌ Set SOLVER_MANAGER_CONTRACT_ADDRESS or SOLVER_MANAGER_ADDRESS in .env');
    usage();
    process.exit(1);
  }
  if (!SOLVER_ADDRESS || !ethers.utils.isAddress(SOLVER_ADDRESS)) {
    console.error('❌ Provide a valid solver EVM address (e.g. 0x...) as argument or SOLVER_ADDRESS');
    usage();
    process.exit(1);
  }

  const provider = new ethers.providers.JsonRpcProvider(RPC_URL);
  const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, provider);

  const solverAddress = ethers.utils.getAddress(SOLVER_ADDRESS);

  console.log('SolverManager contract:', CONTRACT_ADDRESS);
  console.log('Solver address to check:', solverAddress);
  console.log('');

  try {
    const validated = await contract.isSolverIdValidated(solverAddress);
    console.log('Validated:', validated);

    try {
      const solverId = await contract.getSolverId(solverAddress);
      if (solverId && solverId !== '') {
        console.log('Solver ID:', solverId);
      }
    } catch (_) {
      // getSolverId may revert if not mapped
    }

    process.exit(validated ? 0 : 1);
  } catch (e) {
    console.error('❌ Error:', e.message);
    process.exit(2);
  }
}

main();
