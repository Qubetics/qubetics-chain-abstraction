import { ethers } from 'ethers';

// Raw signed transaction from your logs
const rawTx = '0xf869800782520894c58b6f3147bd368ac2eb3e8a226c7ed32676cbe688b469471f80140000808246ada024653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1ca05ee6d6934681cced2451ea67b416ab4e51a76fcd253ad7fff2784712efef9b09';

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