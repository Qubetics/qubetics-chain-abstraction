import fs from "fs";
import { Wallet } from "ethers";

let out = "";
for (let i = 0; i < 3; i++) {
  const w = Wallet.createRandom();
  console.log(`ETH ${i + 1} address: ${w.address}`);
  out += `ETH ${i + 1} privateKey: ${w.privateKey}\n`;
}
fs.writeFileSync("generated_keys.txt", out);
console.log("Keys written to generated_keys.txt safely.\n");
