const crypto = require('crypto');

const { hardhat, ethers } = require("hardhat");
const EthCrypto = require('eth-crypto');
const snarkjs = require("snarkjs");
const circomlibjs = require("circomlibjs");
const secp256k1 = require("secp256k1")



function createECDHIdentity() {
	const alice = crypto.createECDH('secp256k1');
    alice.generateKeys();

    // Get public and private keys in hex format
    const publicKey = alice.getPublicKey('hex');
    const privateKey = alice.getPrivateKey('hex');

	const address = EthCrypto.publicKey.toAddress(publicKey);

	return {
        address: address,
        privateKey: privateKey,
        publicKey: publicKey
    };
}


async function test() {

    const alice = createECDHIdentity();
    const bob = createECDHIdentity();

    const dhke = crypto.createECDH('secp256k1');
    dhke.setPrivateKey(alice.privateKey, 'hex');
    const sharedKey = dhke.computeSecret(bob.publicKey, 'hex');

    const message = 'Hello World!';
    const encryptedMessage = await aesEncrypt(message, alice, bob.publicKey);
    const decryptedMessage = await aesDecrypt(encryptedMessage, bob, alice.publicKey);
    console.log(decryptedMessage);


}

function computeSharedKey(sender, receiverPublicKey) {
    const dhke = crypto.createECDH('secp256k1');
    dhke.setPrivateKey(sender.privateKey, 'hex');
    const sharedKey = dhke.computeSecret(receiverPublicKey, 'hex');
    return sharedKey;
}

function aesEncrypt(message, sender, receiverPublicKey) {

    const sharedKey = computeSharedKey(sender, receiverPublicKey);

    const iv = crypto.randomBytes(16);  // Random initialization vector
    const cipher = crypto.createCipheriv('aes-256-cbc', sharedKey.slice(0, 32), iv);  // Use only the first 32 bytes as the key
    let encrypted = cipher.update(message, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return {iv,
        encrypted};
}

function aesDecrypt(encryptedMessage, receiver, SenderPublicKey) {

  const sharedKey = computeSharedKey(receiver, SenderPublicKey);

  // Decrypt the message with the shared secret
  const decipher = crypto.createDecipheriv('aes-256-cbc', sharedKey.slice(0, 32), encryptedMessage.iv);
  let decrypted = decipher.update(encryptedMessage.encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

test();