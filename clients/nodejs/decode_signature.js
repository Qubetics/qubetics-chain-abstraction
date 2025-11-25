import { ethers } from 'ethers';

// Raw signed transaction from your logs
const rawTx = '0xf86201078301c62f9449bb70cad5e237ca1866bf860d3a45b89413498680808246ada024653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1ca0699c5d1c405213662cc3af76d18577c3ab5eaf9c803e6dbc1ec47bfc2cbfd993';

try {
    // Parse the transaction (ethers v6)
    const tx = ethers.Transaction.from(rawTx);
    
    console.log('📝 Transaction Details:');
    console.log('  From (recovered):', tx.from);
    console.log('  To:', tx.to);
    console.log('  Value:', tx.value.toString());
    console.log('  Nonce:', tx.nonce);
    console.log('  Gas Limit:', tx.gasLimit.toString());
    console.log('  Gas Price:', tx.gasPrice?.toString() || 'N/A');
    console.log('  Chain ID:', tx.chainId.toString());
    console.log('');
    console.log('📊 Signature:');
    console.log('  v:', tx.signature?.v);
    console.log('  r:', tx.signature?.r);
    console.log('  s:', tx.signature?.s);
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
