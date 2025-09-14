import { ethers } from "ethers";

const tx = ethers.Transaction.from("0xf86e01843b9aca00830493e09441412376613f318d6a26a89aa330e4d2647cf760880110000000000000808246aea024653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1ca05bc58775f86bddaff9f9e682819b75d57a8c78d9f2776d083333fcc1ad3cbe34");

console.log("Signer Address:", tx.from);
console.log("Chain ID:", tx.chainId);
console.log("Transaction Details:", {
    nonce: tx.nonce,
    gasPrice: tx.gasPrice?.toString(),
    gasLimit: tx.gasLimit?.toString(),
    to: tx.to,
    value: ethers.formatEther(tx.value),
    signature: tx.signature
});
