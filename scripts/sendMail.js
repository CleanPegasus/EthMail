const { hardhat, ethers } = require("hardhat");
const NodeRSA = require('node-rsa');

const EthCrypto = require('eth-crypto');

async function deployEthMail() {
	const EthMail = await ethers.getContractFactory("EthMail");
	const ethMail = await EthMail.deploy();
	await ethMail.deployed();
	console.log("EthMail deployed to:", ethMail.address);
	return ethMail;
}


async function encryptData(publicKey1, publicKey2, message) {

	const encryptedMessage1 = await EthCrypto.encryptWithPublicKey(
    	publicKey1, // publicKey
    	message // message
	);
	const encryptedMessage2 = await EthCrypto.encryptWithPublicKey(
		publicKey2, // publicKey
		message // message
	);

	const encryptedMessage1String = EthCrypto.cipher.stringify(encryptedMessage1);
	const encryptedMessage2String = EthCrypto.cipher.stringify(encryptedMessage2);

	return {encryptedMessage1String, encryptedMessage2String};
}

async function decryptMessage(encryptedMessage, privateKey) {

	const parsedMessage = EthCrypto.cipher.parse(encryptedMessage);
	const decryptedMessage = await EthCrypto.decryptWithPrivateKey(
		privateKey, // privateKey
		parsedMessage // encrypted-data
	);
	return decryptedMessage;
}



async function createIdentity() {
	const sender = EthCrypto.createIdentity();
	const receiver = EthCrypto.createIdentity();

	const senderWallet = new ethers.Wallet(sender.privateKey, ethers.provider);
	const receiverWallet = new ethers.Wallet(receiver.privateKey, ethers.provider);

	// send ETH to sender and receiver
	const [deployer] = await ethers.getSigners();
	await deployer.sendTransaction({
		to: sender.address,
		value: ethers.utils.parseEther("100"),
	});
	await deployer.sendTransaction({
		to: receiver.address,
		value: ethers.utils.parseEther("100"),
	});

	// const ethMail = await deployEthMail();
	// const encodedSenderPublicKey = ethers.utils.defaultAbiCoder.encode(["string"], [sender.publicKey]);
	// await ethMail.connect(senderWallet).registerDomain('sender.ethmail', encodedSenderPublicKey);

	// const encodedReceiverPublicKey = ethers.utils.defaultAbiCoder.encode(["string"], [receiver.publicKey]);
	// await ethMail.connect(receiverWallet).registerDomain('receiver.ethmail', encodedReceiverPublicKey);

	return {sender, receiver, senderWallet, receiverWallet};
}


async function createHandshake(sender, receiver, ethMail) {

	// const {sender, receiver, ethMail} = await createIdentity();

	const receiverPublicKey = (await ethMail.lookup('receiver.ethmail'))[1];

	const receiverPublicKeyDecoded = ethers.utils.defaultAbiCoder.decode(["string"], receiverPublicKey)[0];

	// Create a random string of length 10
	const senderRandomString = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
	// console.log(typeof senderRandomString)
	console.log(`Sender random string: ${senderRandomString}`);

	const encryptedSenderRandomString = await encryptData(sender.publicKey, receiverPublicKeyDecoded, senderRandomString);
	// TODO: send encryptedMessage2String to receiver

	const decryptedSenderRandomString = await decryptMessage(encryptedSenderRandomString.encryptedMessage2String, receiver.privateKey);
	console.log(`Decrypted Sender random string: ${decryptedSenderRandomString}`);

	// Create a receiver random string
	const receiverRandomString = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
	console.log(`Receiver random string: ${receiverRandomString}`);

	const encrptedReceiverRandomString = await encryptData(receiver.publicKey, sender.publicKey, receiverRandomString);

	// TODO: send encryptedMessage4String to sender

	const decryptedReceiverRandomString = await decryptMessage(encrptedReceiverRandomString.encryptedMessage2String, sender.privateKey);
	console.log(`Decrypted Receiver random string: ${decryptedReceiverRandomString}`);

	return { sender, receiver, senderRandomString, receiverRandomString };

}


async function main() {

	// deploy EthMail contract
	const ethMail = await deployEthMail();

	// create sender and receiver identities
	const { sender, receiver, senderWallet, receiverWallet } = await createIdentity();

	// register sender and receiver domains
	const encodedSenderPublicKey = ethers.utils.defaultAbiCoder.encode(["string"], [sender.publicKey]);
	await ethMail.connect(senderWallet).registerDomain('sender.ethmail', encodedSenderPublicKey);

	const encodedReceiverPublicKey = ethers.utils.defaultAbiCoder.encode(["string"], [receiver.publicKey]);
	await ethMail.connect(receiverWallet).registerDomain('receiver.ethmail', encodedReceiverPublicKey);

	// create handshake
	const { senderRandomString, receiverRandomString } = await createHandshake(sender, receiver, ethMail);

	// Send message from sender to receiver
	const message = "Hello World";

	const encryptedMessage = await encryptData(sender.publicKey, receiver.publicKey, message);

	const senderRandomStringHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(senderRandomString));
	// const receiverRandomStringHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(receiverRandomString));

	const tx = await ethMail.connect(senderWallet).sendMessage(encryptedMessage.encryptedMessage2String, senderRandomStringHash);

	await tx.wait();
	console.log(tx.hash)

	// The receiver can now decrypt the message

	const encryptedMessageFromSender = await ethMail.connect(receiverWallet).getMessages(senderRandomStringHash);
	console.log(encryptedMessageFromSender[0])
	const decryptedMessage = await decryptMessage(encryptedMessageFromSender[0], receiver.privateKey);
	console.log(decryptedMessage);


}


main();