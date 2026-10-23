import { ethers } from 'ethers';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

dotenv.config({ path: join(__dirname, '../../.env') });

const provider = new ethers.providers.JsonRpcProvider(process.env.RPC_URL);

// User 1's private key (from test_sequencer_parallel.js)
const FUNDER_PK = process.env.FUNDER_PK;
const funderWallet = new ethers.Wallet(FUNDER_PK, provider);

// Amount to send: 200 TICS
const AMOUNT = ethers.utils.parseEther('200');

// Derived addresses for users 104-204 (excluding those without derived addresses: 128, 133, 134, 166, 175, 203)
const derivedAddresses = [
  { userId: 104, address: '0xbaa7766010502300b967e99b0cf36c15bac86f8d' },
  { userId: 105, address: '0xdc79b021222b4a2f51edbdd11897baa45102d246' },
  { userId: 106, address: '0x3ec898f01201e49f528dd7a33b3635d905ab8ed9' },
  { userId: 107, address: '0xb489dd5b07c24f7dfc5aa1822fb21e54d0cd6c40' },
  { userId: 108, address: '0x1900415549cf665c3996e9b299bb15f0a7b07263' },
  { userId: 109, address: '0x03f633d028580aac3cc95299cee87006b88127cc' },
  { userId: 110, address: '0xe1d5d371b56ae4e44ae3a7657d32fc0a347e638b' },
  { userId: 111, address: '0x42f306be76d14e42c583f1c543ba24c18ee1350b' },
  { userId: 112, address: '0x5b2789efa7e41c2664ab5e6c9721d799dbede585' },
  { userId: 113, address: '0xc9f5f8533bf5a3de8b151b932f6475897514f018' },
  { userId: 114, address: '0x7eb960e5776e5274b884fbbc088ec180cc9a663b' },
  { userId: 115, address: '0xb9370199e5648b5a9453e31994c8175f84ae74ef' },
  { userId: 116, address: '0xa5149bd547adfc30fb73412f17bb26308ae28f53' },
  { userId: 117, address: '0xd74f635295a1f668e5be6d127751f47050ea564c' },
  { userId: 118, address: '0x2378e2f0b3d4a581d1f170307f672e4362220c07' },
  { userId: 119, address: '0x67a55fc97d84cf05285c13278bbb81a2a77c945d' },
  { userId: 120, address: '0x2df072b3def38d3274c378f97774340c97bc0245' },
  { userId: 121, address: '0x494e1d883c23614dd2c47e86407c9e1bfde955c6' },
  { userId: 122, address: '0x9fafd0a83b535f2a53de149490d5095ec16e7ab7' },
  { userId: 123, address: '0x44b22a7dd39a8e79dcc9c71cd167e5411ab3a127' },
  { userId: 124, address: '0xcfb8acf202c54530eefd684380127e0f66ade6db' },
  { userId: 125, address: '0xb75fec872aebad8241fcb339032369a456e6a3e6' },
  { userId: 126, address: '0x1cf32a7448af9cb6c29dde03493463465eb7283d' },
  { userId: 127, address: '0xc3d72757c7d6934855d3f472081984842213a03e' },
  // 128 has no derived address
  { userId: 129, address: '0x32c0892420c2cdfba1e8f856d4b37f151a234674' },
  { userId: 130, address: '0x1b45a74909a915bb6f49b94ce28d0d23598b7180' },
  { userId: 131, address: '0xdb1403eab3691b1a3a7ab4cf7acc8cb75dc39c6c' },
  { userId: 132, address: '0x6c0e0cc192071d94d38ba653fbc4a095fe17a92c' },
  // 133 has no derived address
  // 134 has no derived address
  { userId: 135, address: '0xedc33e7226b84b7d039b8e317bc737316e0f7b50' },
  { userId: 136, address: '0x669089586f1a8b2325d67776155c53cb1ff0ec90' },
  { userId: 137, address: '0x7d992321eb379ef23e44e6e52b087049cda48a21' },
  { userId: 138, address: '0x2ae6ca8c1bd9041e3fdb1f81d711b7afed3f459d' },
  { userId: 139, address: '0x91a2b2a7b982744fb48cf45e599fefa9e3f7c894' },
  { userId: 140, address: '0x473cbadf7a5a921352da1e2fd525bdea7d0b9a9c' },
  { userId: 141, address: '0x0ee916322509117bb69ddba796014af0a4cb1d32' },
  { userId: 142, address: '0x749b1946bc3be7824cdd557c0415a300087446f9' },
  { userId: 143, address: '0x9ca68226c7e5b50888e456248b49c8e0e0af8053' },
  { userId: 144, address: '0x733d9e6fc4af9284f47757d6d569e5f36fa051b0' },
  { userId: 145, address: '0xb7600061f60732733d318330969b3deaa21015fb' },
  { userId: 146, address: '0xebb42bafbcb47612506953f6c97d37bd3335dbc3' },
  { userId: 147, address: '0xe11b5020ccceb0c73f57888e0db3fd402ffb3c9f' },
  { userId: 148, address: '0x3623e391c6ab1734de762ef90e98856f889ad0ec' },
  { userId: 149, address: '0x2a277c8eef5cd8d8c9803c54c3e1ee82af45c04f' },
  { userId: 150, address: '0xd8d819f8e4ffee4d3c26280b49417419682a6736' },
  { userId: 151, address: '0xc2d2e6a90bc9369a967d6e6e06db0a83d4a44fd4' },
  { userId: 152, address: '0x29452a9e42edbf539f7a0b065d93933c6eb4b52d' },
  { userId: 153, address: '0xf569c88dd6111e3ca81734f5ecc922b2a3f88558' },
  { userId: 154, address: '0xa13023b6739794f0d4bcbbe6ad737aefe0d9b448' },
  { userId: 155, address: '0x1382473aef74b5c53778df0e138ae05fae6d83c9' },
  { userId: 156, address: '0x139a2127bd8140ff519aa3590751af6432c94f4f' },
  { userId: 157, address: '0xd8f8ddd59a8b4c949a52ff10afc4d2c9c32373d6' },
  { userId: 158, address: '0x39cdf87110f40822f4706d72340aab17f6418abe' },
  { userId: 159, address: '0x4f26cc1bdf1826aef755b7e1e04d5ea6152e1ffe' },
  { userId: 160, address: '0x75497809e7bffe8d994db7ef0152e2985345ca45' },
  { userId: 161, address: '0x6af42b40bdacb17fe761f078b8397ea295a4020b' },
  { userId: 162, address: '0x61b2e07f0e5e5721c6336246982615b728456a22' },
  { userId: 163, address: '0x0b1d0788a32df20faa21b1173c7309dee34f4bb6' },
  { userId: 164, address: '0x2bb892caf4de9003004c4d747e7e93fc46f9f3a8' },
  { userId: 165, address: '0x7db3a2ea18924eb9249bb793292c7ebc7f15914d' },
  // 166 has no derived address
  { userId: 167, address: '0x68212c5f49839cfbcd677b55b944a7aab4ad5c9e' },
  { userId: 168, address: '0x366d69aa98bf37d3d8692a37d795e110a6958721' },
  { userId: 169, address: '0x51ea8b837830d6a0f9091dc3656af3851fc1b720' },
  { userId: 170, address: '0xad262173caea1f42c24b46d867fe8e390e54ba6b' },
  { userId: 171, address: '0xc8be26803285d401cf718af059d4d46db55c10bf' },
  { userId: 172, address: '0x68323aff35803aa837b46c515106d589636748d6' },
  { userId: 173, address: '0xa911221a387a5dcaa6749fce509fee78d0ae7304' },
  { userId: 174, address: '0x68aa4b728f99146c29561a041b8f7fb3fb349eb3' },
  // 175 has no derived address
  { userId: 176, address: '0x7a7e7a46c0b2968451911865e445e095c1edea31' },
  { userId: 177, address: '0x51998695b0d52a833af45c36ca8e184921860243' },
  { userId: 178, address: '0x422f5bfb2d960342bd9fb68928fadd43db2b594d' },
  { userId: 179, address: '0xf919104ad4738b005a8afb9e5df9812d88523e32' },
  { userId: 180, address: '0x5ac5aece9dadaf2ea666950bfc37e33a3dc3b2eb' },
  { userId: 181, address: '0xb0933612bcc43bdcc726a3f57c74137132da6192' },
  { userId: 182, address: '0x69f2e079c46a5f844de61a806affba88adbbc1bd' },
  { userId: 183, address: '0x66d1800d293dfca76d42509b929c889a04a28a2f' },
  { userId: 184, address: '0xef672c2a0a4e647ee0ca9af5ae7003981d6b0983' },
  { userId: 185, address: '0x86d86c677325d28f9446e071106fb01f93a3929c' },
  { userId: 186, address: '0x12e2d36409c9165a3408c26de3bab9885864d398' },
  { userId: 187, address: '0x02d4a48cc368aaa8a5690dd3736222f872c4ff2f' },
  { userId: 188, address: '0xba5ba39deed0dd31cd561d810d6fcfe69870c4a5' },
  { userId: 189, address: '0x6fdd3906d605d2a5dfac111e7e8c12edac880022' },
  { userId: 190, address: '0x6e29d4ab3db3f06a9a85725e78e6b7addc2b6c9c' },
  { userId: 191, address: '0xa6d704260a1350800ea574245b82344dc64e68da' },
  { userId: 192, address: '0x15df7629684416bf8713afd1223f100bb2dfd635' },
  { userId: 193, address: '0xb1557b66799d3a245bde92eb35016e1f12255ee4' },
  { userId: 194, address: '0x3df90b711b8cc62bff7d3abe47b5c92ff5fd9813' },
  { userId: 195, address: '0xede7aac88ed68503737c28c93236d208b865dce9' },
  { userId: 196, address: '0x6b54f41c46c632628b27fcc84435b198f70b9f11' },
  { userId: 197, address: '0x0c90ad6e53fa3bf66e5e0de04c400e140f5d91a6' },
  { userId: 198, address: '0xc55a973a15a3be428e1d7a8b10bf0ad4b2c96382' },
  { userId: 199, address: '0x07101fdbeac64e7f29da5b7006dd706640580279' },
  { userId: 200, address: '0xdcb8b693f4327db3de84f0671ae532ed376fd235' },
  { userId: 201, address: '0x0647dcdf56df144736e9a5381efdd22b5dea2872' },
  { userId: 202, address: '0x1788b7e1daf98a03e9d9bfef52969f3b069554e1' },
  // 203 has no derived address
  { userId: 204, address: '0xcdb268eaf1768e052174fa76d4c9a1d2b7e4d618' },
];

async function main() {
  console.log('');
  console.log('\x1b[1mFunding Users 104-204 with 200 TICS each\x1b[0m');
  console.log('');

  const funderBalance = await provider.getBalance(funderWallet.address);
  console.log(`Funder: ${funderWallet.address}`);
  console.log(`Funder Balance: ${ethers.utils.formatEther(funderBalance)} TICS`);
  console.log(`Total addresses to fund: ${derivedAddresses.length}`);
  console.log(`Total TICS needed: ${derivedAddresses.length * 200} TICS`);
  console.log('');

  let successCount = 0;
  let failCount = 0;

  for (const { userId, address } of derivedAddresses) {
    try {
      const tx = await funderWallet.sendTransaction({
        to: address,
        value: AMOUNT,
      });
      await tx.wait();
      console.log(`✓ User ${userId}: ${address} funded (tx: ${tx.hash.slice(0, 10)}...)`);
      successCount++;
    } catch (err) {
      console.log(`✗ User ${userId}: ${address} FAILED - ${err.message}`);
      failCount++;
    }
  }

  console.log('');
  console.log('\x1b[1mSummary\x1b[0m');
  console.log(`Success: ${successCount}`);
  console.log(`Failed: ${failCount}`);
  console.log(`Total TICS transferred: ${successCount * 200} TICS`);
  console.log('');
}

main().catch(console.error);
