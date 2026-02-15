import { ethers } from 'ethers';

// Raw signed transaction from your logs
const rawTx = '0xf901ec05843b9aca00830255b794390bbee9a268f273f3f5af09bb5ae59516dd832780b90184120d136d00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000056bc75e2d63100000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000000a534f4c5645525f303031000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000025746963735f77697468647261775f62617463683a3432353a313737303730323635343030330000000000000000000000000000000000000000000000000000008246aea0070dac308fbb0ff8a14bf96d70036080bdd1336517807ef73471a442a9b1bae9a0324d058b93e23e3d76053ff4d640e105713cf297b8d038d0d3621dacec234d1f';

try {
    // Parse the transaction (ethers v5)
    const tx = ethers.utils.parseTransaction(rawTx);

    console.log('📝 Transaction Details:');
    console.log('  From (recovered):', tx.from);
    console.log('  To:', tx.to);
    console.log('  Value:', tx.value.toString());
    console.log('  Nonce:', tx.nonce);
    console.log('  Gas Limit:', tx.gasLimit.toString());
    console.log('  Gas Price:', tx.gasPrice?.toString() || 'N/A');
    console.log('  Chain ID:', tx.chainId || 'N/A');
    console.log('');
    console.log('📊 Signature:');
    console.log('  v:', tx.v);
    console.log('  r:', tx.r);
    console.log('  s:', tx.s);
    console.log('');
    console.log('🔍 The signature recovers to address:', tx.from);
    console.log('');
    console.log('⚠️  THIS IS THE ADDRESS YOUR NODES ARE USING!');
    console.log('    Send TICS tokens to:', tx.from);
    console.log('');
    console.log('💡 The "insufficient funds" error means this address has 0 TICS.');
    console.log('   You need to fund this address on the Qubetics testnet!');

} catch (error) {
    console.error('Error:', error.message);
    console.error(error.stack);
}