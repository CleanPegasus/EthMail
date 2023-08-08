const { hardhat, ethers } = require("hardhat");
const EthCrypto = require('eth-crypto');
const snarkjs = require("snarkjs");
const circomlibjs = require("circomlibjs");


// Mine N Blocks
async function mineBlocks(blocks) {
    for (let i = 0; i < blocks; i++) {
      await ethers.provider.send("evm_mine", []);
    }
}

async function deployContracts() {
	const Verifier = await ethers.getContractFactory("Groth16Verifier");
    const verifier = await Verifier.deploy();
    await verifier.deployed();
    console.log("Verifier deployed to:", verifier.address);
	const EthMail = await ethers.getContractFactory("EthMail");
	const ethMail = await EthMail.deploy(verifier.address);
	await ethMail.deployed();
	console.log("EthMail deployed to:", ethMail.address);
	return ethMail;
}


async function encryptData(publicKey, message) {
	const encryptedMessage = await EthCrypto.encryptWithPublicKey(
		publicKey, // publicKey
		message // message
	);

	return EthCrypto.cipher.stringify(encryptedMessage);
}


async function encryptDataTwoWay(publicKey1, publicKey2, message) {

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

	return {sender, receiver, senderWallet, receiverWallet};
}

function createRandomNumber() {
	// Generate a random 32-byte hexadecimal number
    const randomBytes = ethers.utils.randomBytes(32);
    
    // Convert the random bytes to a BigNumber
    const randomNumber = ethers.BigNumber.from(randomBytes);
    
    return randomNumber.toString();
}


async function createHandshake(sender, senderWallet, receiverEthMail, ethMail) {

	const receiverPublicKey = (await ethMail.lookup(receiverEthMail))[1];
	const receiverAddress = (await ethMail.lookup(receiverEthMail))[0];

	const receiverPublicKeyDecoded = ethers.utils.defaultAbiCoder.decode(["string"], receiverPublicKey)[0];
	console.log(`Receiver public key: ${receiverPublicKeyDecoded}`);

	// Create a random string of length 10
	const senderRandomString = createRandomNumber();
	// console.log(typeof senderRandomString)
	console.log(`Sender random string: ${senderRandomString}`);

	const encryptedSenderRandomString = await encryptDataTwoWay(sender.publicKey, receiverPublicKeyDecoded, senderRandomString);
	console.log('Encrypted Sender random string: ', encryptedSenderRandomString.encryptedMessage2String)

	const tx = await ethMail.connect(senderWallet).createHandshake(receiverAddress, ethers.utils.hexlify(ethers.utils.toUtf8Bytes(encryptedSenderRandomString.encryptedMessage2String)));
	await tx.wait();

	return tx.hash;

}

async function completeHandshake(receiver, receiverWallet, ethMail) {

	const encryptedSenderRandomString = ethers.utils.toUtf8String((await ethMail.getAddedUsers(receiverWallet.address))[0]);

	const senderPublicKey = (await ethMail.lookup('sender.ethmail'))[1];
	const senderPublicKeyDecoded = ethers.utils.defaultAbiCoder.decode(["string"], senderPublicKey)[0];

	const senderAddress = (await ethMail.lookup('sender.ethmail'))[0];

	const decryptedSenderRandomString = await decryptMessage(encryptedSenderRandomString, receiver.privateKey);
	console.log(`Decrypted Sender random string: ${decryptedSenderRandomString}`);

	// Create a receiver random string
	const receiverRandomString = createRandomNumber();
	console.log(`Receiver random string: ${receiverRandomString}`);

	// Create and encode the handshake between the sender and the receiver
	const senderHandshakeRandomStrings = {
		receiver: 'receiver.ethmail',
		senderRandomString: decryptedSenderRandomString,
		receiverRandomString: receiverRandomString
	}

	const encodedSenderHandshakeRandomStrings = JSON.stringify(senderHandshakeRandomStrings)

	const receiverHandshakeRandomStrings = {
		receiver: 'sender.ethmail',
		senderRandomString: receiverRandomString,
		receiverRandomString: decryptedSenderRandomString
	}

	const encodedReceiverHandshakeRandomStrings = JSON.stringify(receiverHandshakeRandomStrings)
	// Encrypt the handshake with the public keys of the sender and the receiver
	const encryptedSenderRandomStrings = await encryptData(senderPublicKeyDecoded, encodedSenderHandshakeRandomStrings);
	const encryptedReceiverRandomStrings = await encryptData(receiver.publicKey, encodedReceiverHandshakeRandomStrings);

	console.log(encryptedSenderRandomStrings)

	let encryptedSenderRandomHexs = ethers.utils.hexlify(ethers.utils.toUtf8Bytes(JSON.stringify(encryptedSenderRandomStrings)));
	let encryptedReceiverRandomHexes = ethers.utils.hexlify(ethers.utils.toUtf8Bytes(JSON.stringify(encryptedReceiverRandomStrings)));

	console.log(encryptedReceiverRandomHexes)

	// Complete the handshake
	const tx = await ethMail.connect(receiverWallet).completeHandshake(senderAddress, encryptedReceiverRandomHexes, encryptedSenderRandomHexs);
	await tx.wait();

	// return { senderRandomString, receiverRandomString };
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function createProof(randomString, nonce) {

	const randomStringBigInt = ethers.BigNumber.from(randomString).toBigInt();

	const poseidon = await circomlibjs.buildPoseidon();
	const hash = poseidon.F.toString(poseidon([randomStringBigInt]));
	console.log('hash:', hash)
	const hash_with_nonce = poseidon.F.toString(poseidon([randomStringBigInt, nonce]));

	const {proof, publicSignals} = await snarkjs.groth16.fullProve(
		{ preImage: randomStringBigInt, nonce: nonce, preImageHash: hash, hashedValue: hash_with_nonce },
		"build/nonce_hasher_js/nonce_hasher.wasm", 
        "circuit_0000.zkey");
	// console.log('publicSignals:', publicSignals)
	const calldatas = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals);
	const formattedCalldata = JSON.parse('[' + calldatas + ']');
	// console.log('formattedCalldata:', formattedCalldata[3])

	return formattedCalldata;

}

async function sendMessage(sender, senderWallet, receiver, message, ethMail) {

	const encryptedMessage = JSON.stringify(await encryptDataTwoWay(sender.publicKey, receiver.publicKey, message));

	const senderHandshakes = await ethMail.getHandshakes(senderWallet.address);
	// console.log(senderWallet.address)
	console.log(senderHandshakes)

	const encryptedSenderRandomString = JSON.parse(ethers.utils.toUtf8String(senderHandshakes[0]));
	console.log(encryptedSenderRandomString)

	const decryptedSenderKey = JSON.parse(await decryptMessage(encryptedSenderRandomString, sender.privateKey));
	console.log(decryptedSenderKey.senderRandomString)

	const senderHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(decryptedSenderKey.senderRandomString));

	console.log('Sender hash: ', senderHash)

	const lastMessageHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(encryptedMessage + Date.now().toString()));
	const nonce = (await ethMail.getNonce(senderWallet.address)).toBigInt();
	const calldatas = await createProof(decryptedSenderKey.senderRandomString, nonce);

	const tx = await ethMail.connect(senderWallet).sendMessage(encryptedMessage, lastMessageHash, calldatas[0], calldatas[1], calldatas[2], calldatas[3]);
	await tx.wait();
	console.log('Message sent')
	
}

async function checkMessages(receiver, ethMail) {

	const receiverHandshakes = await ethMail.getHandshakes(receiver.address);

	const encryptedReceiverRandomString = JSON.parse(ethers.utils.toUtf8String(receiverHandshakes[0]));
	console.log(encryptedReceiverRandomString)

	const decryptedReceiverKey = JSON.parse(await decryptMessage(encryptedReceiverRandomString, receiver.privateKey));
	console.log(decryptedReceiverKey.receiverRandomString)

	// const receiverHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(decryptedReceiverKey.receiverRandomString));

	const poseidon = await circomlibjs.buildPoseidon();
	const receiverHash = poseidon.F.toString(poseidon([BigInt(decryptedReceiverKey.receiverRandomString)]));

	console.log('Receiver hash: ', receiverHash)

	const messages = JSON.parse((await ethMail.getMessages(receiverHash))[0]);

	const decryptedMessage = await decryptMessage(messages.encryptedMessage2String, receiver.privateKey);
	// console.log(decryptedMessage)

	return decryptedMessage;
}


async function main() {

	// deploy EthMail contract
	const ethMail = await deployContracts();

	// create sender and receiver identities
	const { sender, receiver, senderWallet, receiverWallet } = await createIdentity();

	// register sender and receiver domains
	const encodedSenderPublicKey = ethers.utils.defaultAbiCoder.encode(["string"], [sender.publicKey]);
	await ethMail.connect(senderWallet).registerDomain('sender.ethmail', encodedSenderPublicKey);

	const encodedReceiverPublicKey = ethers.utils.defaultAbiCoder.encode(["string"], [receiver.publicKey]);
	await ethMail.connect(receiverWallet).registerDomain('receiver.ethmail', encodedReceiverPublicKey);

	// create handshake
	const { senderRandomString, receiverRandomString } = await createHandshake(sender, senderWallet, 'receiver.ethmail', ethMail);

	console.log('Handshake created')

	// Complete handshake
	await completeHandshake(receiver, receiverWallet, ethMail);
	console.log('Handshake completed')

	mineBlocks(100)

	// Send message from sender to receiver
	const message = "Hello World";

	await sendMessage(sender, senderWallet, receiver, message, ethMail);
	

	mineBlocks(100)

	const decryptedMessage = await checkMessages(receiver, ethMail);
	console.log(decryptedMessage)

}


main().then(() => process.exit(0)).catch(error => {
	console.error(error);
	process.exit(1);
});