const secp256k1 = require('secp256k1');
const keccak256 = require('keccak');

const privateKey = '93cc7fbc4bfd7fcfd83d11c85ba522f8fa1c03ece1a3b5f1782bc164996844d9';
const privateKeyBuffer = Buffer.from(privateKey, 'hex');

const publicKey = secp256k1.publicKeyCreate(privateKeyBuffer, false);
console.log('Public key (uncompressed):', publicKey.toString('hex'));

const publicKeyWithoutPrefix = publicKey.slice(1);
console.log('Public key without 0x04 prefix:', publicKeyWithoutPrefix.toString('hex'));

const hasher = keccak256('keccak256');
hasher.update(publicKeyWithoutPrefix);
const hash = hasher.digest();

console.log('Keccak256 hash:', hash.toString('hex'));
console.log('Last 20 bytes:', hash.slice(-20).toString('hex'));

const address = '0x' + hash.slice(-20).toString('hex');
console.log('\nDerived address:', address);

