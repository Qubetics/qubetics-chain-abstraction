const secp256k1 = require('secp256k1');
const keccak256 = require('keccak');

function deriveAddress(privateKeyHex) {
    const privateKey = privateKeyHex.startsWith('0x') ? privateKeyHex.slice(2) : privateKeyHex;
    const privateKeyBuffer = Buffer.from(privateKey, 'hex');
    
    const publicKey = secp256k1.publicKeyCreate(privateKeyBuffer, false);
    const publicKeyWithoutPrefix = publicKey.slice(1);
    
    const hasher = keccak256('keccak256');
    hasher.update(publicKeyWithoutPrefix);
    const hash = hasher.digest();
    
    const address = '0x' + hash.slice(-20).toString('hex');
    return address;
}

const pk = '0x93cc7fbc4bfd7fcfd83d11c85ba522f8fa1c03ece1a3b5f1782bc164996844d9';
const addr = deriveAddress(pk);
console.log('Derived address:', addr);
console.log('Expected:', '0xf71736a05f5673da815c1853378ff12c1aad4ff6');
console.log('Got:', '0xf75A3D99fA81dB6973Bc620C05F45902fB80d4f6');
