import { ethers } from "ethers";

const tx = ethers.Transaction.from("0xf86c80843b9aca00830493e094c62d0c0aa7279a3c3a4f3000b0e255268fdd01a38609184e72a000808246aea024653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1ca01877ffc06f43cb8f5bce0ccc5c709a5c18e833e1fcf341745dbdcf32f8f6b2c6");

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
