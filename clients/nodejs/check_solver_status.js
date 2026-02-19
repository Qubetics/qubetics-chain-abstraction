#!/usr/bin/env node

/**
 * Check solver status on the SolverManager contract for all configured solver IDs.
 *
 * Usage:
 *   node check_solver_status.js
 */

import { ethers } from 'ethers';

const RPC_URL = 'https://rpc-testnet.qubetics.work';
const CONTRACT_ADDRESS = '0x245c74C270da4ac636e6af576e6781c6d2302e91';

const SOLVER_IDS = [
  '12D3KooWRHszGRqaTCY6Meo2m4Vvmu8v5aWc64keyAsHFhwen4pF',
  '12D3KooWPhjHR6zK4hfxSy8Dn11kNQuAGQfrxAG8WoPoyhDwmuBZ',
  '12D3KooWSp1v1u6s6T9AcVs3b86T7MGY3dBBTUBjXUob2ibRJ2EC',
  '12D3KooWQ8RsvGtHakkeVKVbTJUoivmjGmRx5wCXmx3zAGw6XYWH',
  '12D3KooWKbuvWs4HYgAQyE37rwdKwJcBX6xmzLx8EHNEh77VBGSs',
  '12D3KooWT1DhsUaYRBVsDw7TLdoo6KRy8PnmtdZUeUFxKWRCLsnc',
  '12D3KooWBqVFs6czTRQzFAEW5vqVYcN2JMrQ9kbjwo6vhuqcPHaa',
  '12D3KooWSpfGMSwDieftKpPUuxrN2bPKasHhAWLMqVSN5owLGTYD',
  '12D3KooWDG2KF88ZrdGH8dW44ESEWL2RucRyhBjugyVZbyBTLhrB',
  '12D3KooWRXoevUW2Krpn6dyoC9azTPaLFavihLGN5DoQj9XCYMN3',
];

const ABI = [
  'function isSolverActive(string) view returns (bool)',
  'function isSolverOnboarded(string) view returns (bool)',
  'function isSolverIdValidated(string) view returns (bool)',
  'function getSolver(string) view returns (tuple(string,string,uint256[],string[],bool,bool,uint256,uint256))',
  'function getSolverId(address) view returns (string)',
  'function getSolverEvmAddress(string) view returns (address)',
  'function getSolverAllChainAmounts(string) view returns (uint256[])',
  'function getActiveSolvers() view returns (string[])',
];

async function checkSolver(contract, solverId) {
  console.log(`========================================`);
  console.log(`  ${solverId}`);
  console.log(`========================================`);

  // isSolverActive
  try {
    const active = await contract.isSolverActive(solverId);
    console.log(`  Active:    ${active ? '✅ true' : '❌ false'}`);
  } catch (e) {
    console.log(`  Active:    ⚠️  error - ${e.message}`);
  }

  // isSolverOnboarded
  try {
    const onboarded = await contract.isSolverOnboarded(solverId);
    console.log(`  Onboarded: ${onboarded ? '✅ true' : '❌ false'}`);
  } catch (e) {
    console.log(`  Onboarded: ⚠️  error - ${e.message}`);
  }

  // isSolverIdValidated — now takes solverId string directly
  try {
    const validated = await contract.isSolverIdValidated(solverId);
    console.log(`  Validated: ${validated ? '✅ true' : '❌ false'}`);
  } catch (e) {
    console.log(`  Validated: ⚠️  error - ${e.message}`);
  }

  // getSolver (struct details)
  // Struct: [0]solverId, [1]solverName, [2]chainIds, [3]solverAddresses, [4]isActive, [5]isOnboarded, [6]onboardedAt, [7]offboardedAt
  try {
    const info = await contract.getSolver(solverId);
    console.log(`  Details:`);
    console.log(`    Name:      ${info[1]}`);
    console.log(`    Chain IDs: [${info[2].map((c) => c.toString()).join(', ')}]`);
    console.log(`    Addresses: [${info[3].join(', ')}]`);
    console.log(`    Active:    ${info[4]}`);
    console.log(`    Onboarded: ${info[5]}`);
    console.log(`    OnboardAt: ${new Date(info[6].toNumber() * 1000).toISOString()}`);
  } catch (e) {
    console.log(`  Details:   ⚠️  getSolver reverted - ${e.message}`);
  }

  // Chain liquidity
  try {
    const amounts = await contract.getSolverAllChainAmounts(solverId);
    if (amounts.length > 0) {
      console.log(`  Liquidity:`);
      amounts.forEach((amt, i) => {
        console.log(`    Chain[${i}]: ${amt.toString()}`);
      });
    }
  } catch (_) {}

  console.log('');
}

async function main() {
  const provider = new ethers.providers.JsonRpcProvider(RPC_URL);
  const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, provider);

  console.log(`\nContract: ${CONTRACT_ADDRESS}`);
  console.log(`RPC:      ${RPC_URL}`);
  console.log(`Checking ${SOLVER_IDS.length} solvers...\n`);

  for (const solverId of SOLVER_IDS) {
    await checkSolver(contract, solverId);
  }
}

main().catch((err) => {
  console.error(`❌ ${err.message}`);
  process.exit(1);
});
