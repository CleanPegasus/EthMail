pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";


template Main() {
    signal input preImage;    // Private input: the pre-image
    signal input nonce;        // Public input: the nonce
    signal input preImageHash; // Public input: hash of the pre-image
    signal input hashedValue;  // Public input: hash of the pre-image concatenated with nonce

    component hashPreImage = Poseidon(1);  // Component to compute hash of preImage
    component hashWithNonce = Poseidon(2); // Component to compute hash of preImage concatenated with nonce

    hashPreImage.inputs[0] <== preImage;
    preImageHash === hashPreImage.out;

    hashWithNonce.inputs[0] <== preImage;
    hashWithNonce.inputs[1] <== nonce;
    hashedValue === hashWithNonce.out;
}

// component main = Main();
component main {public [nonce, preImageHash, hashedValue]} = Main();