import { ethers } from "ethers";

const tx = ethers.Transaction.from("0xf86f80843b9aca00830493e094c9b6a913d243e217feacc0d44aef80f42871c44089014e312fc3ad566000808246ada024653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1ca021eb9f722b44c5bebcb5273d3088322018b8b4f0d34d33469169b56c0730c43c");

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
