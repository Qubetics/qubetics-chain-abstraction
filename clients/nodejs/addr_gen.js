import { Wallet } from "ethers";

for (let i = 0; i < 3; i++) {
  const w = Wallet.createRandom();
  console.log(`ETH ${i + 1} address: ${w.address}`);
  console.log(`ETH ${i + 1} privateKey: ${w.privateKey}\n`);
}
