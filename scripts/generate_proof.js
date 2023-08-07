const { hardhat, ethers } = require("hardhat");

const snarkjs = require("snarkjs");
const circomlibjs = require("circomlibjs");
const fs = require("fs");
// const { bigInt } = require('snarkjs');

  
async function deployVerifier() {
    const Verifier = await ethers.getContractFactory("Groth16Verifier");
    const verifier = await Verifier.deploy();
    await verifier.deployed();
    console.log("Verifier deployed to:", verifier.address);
    return verifier;
}

async function main() {

    const accounts = await ethers.getSigners();
    const verifier = await deployVerifier();

    // const inputBigInts = [10];
    const input = ethers.BigNumber.from(10).toBigInt();

    const poseidon = await circomlibjs.buildPoseidon();
    const hash = poseidon.F.toString(poseidon([input]));
    console.log(hash);

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        { in: input, hash: hash }, 
        "build/poseidon_hasher_js/poseidon_hasher.wasm", 
        "circuit_0000.zkey");

    // fs.writeFileSync('proof.json', JSON.stringify(proof));
    // fs.writeFileSync('public.json', JSON.stringify(publicSignals));

    const vKey = JSON.parse(fs.readFileSync("verification_key.json"));
    const res = await snarkjs.groth16.verify(vKey, publicSignals, proof);
    
    if (res === true) {
        console.log("Verification OK");
    } else {
        console.log("Invalid proof");
    }

    const calldatas = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals);
    const formattedCalldata = JSON.parse('[' + calldatas + ']');
    // console.log('calldatas:', formattedCalldata);
    

    const result = await verifier.verifyProof(formattedCalldata[0], formattedCalldata[1], formattedCalldata[2], formattedCalldata[3]);
    console.log(result);
}

main()