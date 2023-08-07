const { hardhat, ethers } = require("hardhat");

const snarkjs = require("snarkjs");
const circomlibjs = require("circomlibjs");
const fs = require("fs");

  
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

    const poseidon = await circomlibjs.buildPoseidon();
    const hash = poseidon.F.toString(poseidon([10]));
    console.log(hash);

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        { in: 10, hash: hash }, 
        "build/poseidon_hasher_js/poseidon_hasher.wasm", 
        "circuit_0000.zkey");

    const vKey = JSON.parse(fs.readFileSync("verification_key.json"));
    const res = await snarkjs.groth16.verify(vKey, publicSignals, proof);
    
    if (res === true) {
        console.log("Verification OK");
    } else {
        console.log("Invalid proof");
    }
    
    console.log('pi_a:', proof['pi_a'].pop());
    console.log('pi_b:', proof['pi_b'].pop());
    console.log('pi_c:', proof['pi_c'].pop());
    console.log('publicSignal:', publicSignals);

    const result = await verifier.verifyProof(proof['pi_a'], proof['pi_b'], proof['pi_c'], publicSignals);
    console.log(result);
}

main()