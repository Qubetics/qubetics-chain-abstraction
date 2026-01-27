import { ethers } from 'ethers';

// Raw signed transaction from your logs
const rawTx = '0xf86f80843b9aca00830493e094a22ef8e46601df391ca61642bcfefdc981e935e88901896f6ecb96530000808246ada024653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1ca071c1379a7dc2813cf1277903dcaf47eecac5419f2a193effb182c003ce0f1bc7';

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