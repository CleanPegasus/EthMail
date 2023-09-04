const { hardhat, ethers } = require("hardhat");
const EthCrypto = require("eth-crypto");
const snarkjs = require("snarkjs");
const circomlibjs = require("circomlibjs");

const crypto = require("crypto");

// const eccrypto = require("eccrypto");

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

function computeSharedKey(sender, receiverPublicKey) {
  const dhke = crypto.createECDH("secp256k1");
  dhke.setPrivateKey(sender.privateKey, "hex");
  const sharedKey = dhke.computeSecret(receiverPublicKey, "hex");
  return sharedKey;
}

function aesEncrypt(message, sharedKey) {
  const iv = crypto.randomBytes(16); // Random initialization vector
  const cipher = crypto.createCipheriv(
    "aes-256-cbc",
    sharedKey.slice(0, 32),
    iv
  ); // Use only the first 32 bytes as the key
  let encrypted = cipher.update(message, "utf8", "hex");
  encrypted += cipher.final("hex");

  return { iv, encrypted };
}

function aesDecrypt(encryptedMessage, sharedKey) {
  // Decrypt the message with the shared secret
  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    sharedKey.slice(0, 32),
    Buffer.from(encryptedMessage.iv.data)
  );
  let decrypted = decipher.update(encryptedMessage.encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");

  return decrypted;
}

async function encryptData(publicKey, message) {
  const encryptedMessage = await EthCrypto.encryptWithPublicKey(
    publicKey, // publicKey
    message // message
  );

  return EthCrypto.cipher.stringify(encryptedMessage);
}

async function decryptMessage(encryptedMessage, privateKey) {
  const parsedMessage = EthCrypto.cipher.parse(encryptedMessage);
  const decryptedMessage = await EthCrypto.decryptWithPrivateKey(
    privateKey, // privateKey
    parsedMessage // encrypted-data
  );
  return decryptedMessage;
}

function createRandomNumber() {
  // Generate a random 32-byte hexadecimal number
  const randomBytes = ethers.utils.randomBytes(32);

  // Convert the random bytes to a BigNumber
  const randomNumber = ethers.BigNumber.from(randomBytes);

  return randomNumber.toString();
}

async function createHandshake(sender, senderEthMail, senderWallet, receiverEthMail, ethMail) {
  const receiverPublicKey = (await ethMail.lookup(receiverEthMail))[1];
  const receiverAddress = (await ethMail.lookup(receiverEthMail))[0];

  const receiverPublicKeyDecoded = ethers.utils.defaultAbiCoder.decode(
    ["string"],
    receiverPublicKey
  )[0];
  console.log(`Receiver public key: ${receiverPublicKeyDecoded}`);

  // Create a random string of length 10
  const senderRandomString = createRandomNumber();
  const receiverRandomString = createRandomNumber();

  console.log(`Sender random string: ${senderRandomString}`);

  const senderHandshakeRandomStrings = {
    receiver: "receiver.ethMail",
    senderRandomString: senderRandomString,
    receiverRandomString: receiverRandomString,
  };

  const encodedSenderHandshakeRandomStrings = JSON.stringify(
    senderHandshakeRandomStrings
  );

  const receiverHandshakeRandomStrings = {
    receiver: "sender.ethMail",
    senderRandomString: receiverRandomString,
    receiverRandomString: senderRandomString,
  };

  const encodedReceiverHandshakeRandomStrings = JSON.stringify(
    receiverHandshakeRandomStrings
  );
  // Encrypt the handshake with the public keys of the sender and the receiver
  const encryptedSenderRandomStrings = await encryptData(
    sender.publicKey,
    encodedSenderHandshakeRandomStrings
  );
  const encryptedReceiverRandomStrings = await encryptData(
    receiverPublicKeyDecoded,
    encodedReceiverHandshakeRandomStrings
  );

  // Convert the encrypted messages to hex strings
  let encryptedSenderRandomHexs = ethers.utils.hexlify(
    ethers.utils.toUtf8Bytes(JSON.stringify(encryptedSenderRandomStrings))
  );
  let encryptedReceiverRandomHexes = ethers.utils.hexlify(
    ethers.utils.toUtf8Bytes(JSON.stringify(encryptedReceiverRandomStrings))
  );

  const tx = await ethMail
    .connect(senderWallet)
    .createHandshake(
			senderEthMail,
      receiverAddress,
      encryptedSenderRandomHexs,
      encryptedReceiverRandomHexes
    );
  await tx.wait();

  return tx.hash;
}

async function completeHandshake(receiver, receiverEthMail, receiverWallet, ethMail, index) {
  const receiverEncryptedRandomStrings = (
    await ethMail.getAddedUsers(receiverWallet.address)
  )[index];

  const receiverEncryptedRandomStringsDecoded = JSON.parse(
    ethers.utils.toUtf8String(receiverEncryptedRandomStrings)
  );
  console.log(
    "receiverEncryptedRandomStringsDecoded:",
    receiverEncryptedRandomStringsDecoded
  );
  const decryptedReceiverKey = await decryptMessage(
    receiverEncryptedRandomStringsDecoded,
    receiver.privateKey
  );
  console.log("decryptedReceiverKey:", JSON.parse(decryptedReceiverKey));

	const senderAddress = (await ethMail.lookup(JSON.parse(decryptedReceiverKey).receiver))[0];
	console.log("senderAddress:", senderAddress);

  // Complete the handshake
  const tx = await ethMail
    .connect(receiverWallet)
    .completeHandshake(receiverEthMail, senderAddress, receiverEncryptedRandomStrings);
  await tx.wait();
	
	return tx.hash;
  // return { senderRandomString, receiverRandomString };
}

async function createProof(randomString, nonce) {
  const randomStringBigInt = ethers.BigNumber.from(randomString).toBigInt();

  const poseidon = await circomlibjs.buildPoseidon();
  const hash = poseidon.F.toString(poseidon([randomStringBigInt]));
  console.log("hash:", hash);
  const hash_with_nonce = poseidon.F.toString(
    poseidon([randomStringBigInt, nonce])
  );

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    {
      preImage: randomStringBigInt,
      nonce: nonce,
      preImageHash: hash,
      hashedValue: hash_with_nonce,
    },
    "build/nonce_hasher_js/nonce_hasher.wasm",
    "circuit_0000.zkey"
  );
  // console.log('publicSignals:', publicSignals)
  const calldatas = await snarkjs.groth16.exportSolidityCallData(
    proof,
    publicSignals
  );
  const formattedCalldata = JSON.parse("[" + calldatas + "]");

  return formattedCalldata;
}

async function createMessage(senderWallet, message) {
	const detailedMessage = {
		sender: senderWallet.address,
		message: message,
		timestamp: Date.now()
	}
	const signature = await senderWallet.signMessage(JSON.stringify(detailedMessage));
	const signedMessage = {
		message: detailedMessage,
		signature: signature
	}

	return JSON.stringify(signedMessage);
}

async function verifyMessage(signedMessage, senderAddress) {
	const { message, signature } = JSON.parse(signedMessage);

	console.log("message:", message);
	console.log("sign:", signature);

	const recoveredAddress = ethers.utils.verifyMessage(JSON.stringify(message), signature);

	return recoveredAddress === senderAddress;
}

async function sendMessage(sender, senderWallet, receiverEthMail, message, ethMail) {

	const signedMessage = await createMessage(senderWallet, message);
  const receiverPublicKey = (await ethMail.lookup(receiverEthMail))[1];
	const receiverAddress = (await ethMail.lookup(receiverEthMail))[0];
  console.log("receiverPublicKey:", receiverPublicKey);
  const receiverPublicKeyDecoded = ethers.utils.defaultAbiCoder.decode(
    ["string"],
    receiverPublicKey
  )[0];
	const sharedKey = computeSharedKey(sender, receiverPublicKeyDecoded);
  const encryptedMessage = JSON.stringify(
    aesEncrypt(signedMessage, sharedKey)
  );

  const senderHandshakes = await ethMail.getHandshakes(senderWallet.address, receiverAddress);
  // console.log(senderWallet.address)
  console.log(senderHandshakes);

  const encryptedSenderRandomString = JSON.parse(
    ethers.utils.toUtf8String(senderHandshakes)
  );
  console.log(encryptedSenderRandomString);

  const decryptedSenderKey = JSON.parse(
    await decryptMessage(encryptedSenderRandomString, sender.privateKey)
  );
  console.log(decryptedSenderKey.senderRandomString);

  const senderHash = ethers.utils.keccak256(
    ethers.utils.toUtf8Bytes(decryptedSenderKey.senderRandomString)
  );

  console.log("Sender hash: ", senderHash);

  const lastMessageHash = ethers.utils.keccak256(
    ethers.utils.toUtf8Bytes(encryptedMessage + Date.now().toString())
  );
  const nonce = (await ethMail.getNonce(senderWallet.address)).toBigInt();
  const calldatas = await createProof(
    decryptedSenderKey.senderRandomString,
    nonce
  );

  const tx = await ethMail
    .connect(senderWallet)
    .sendMessage(
      encryptedMessage,
      lastMessageHash,
      calldatas[0],
      calldatas[1],
      calldatas[2],
      calldatas[3]
    );
  await tx.wait();
  console.log("Message sent");
}

async function poseidonHash(key) {
	const poseidon = await circomlibjs.buildPoseidon();
	const hash = poseidon.F.toString(poseidon([BigInt(key)]));
	return hash;
}
async function checkMessages(receiver, senderEthMail, ethMail) {

	const senderAddress = (await ethMail.lookup(senderEthMail))[0];
	console.log(ethMail.address);
  const receiverHandshake = await ethMail.getHandshakes(receiver.address, senderAddress);

	console.log("receiverHandshake:", receiverHandshake)
  const encryptedReceiverRandomString = JSON.parse(
    ethers.utils.toUtf8String(receiverHandshake)
  );
  console.log(encryptedReceiverRandomString);

  const decryptedReceiverKey = JSON.parse(
    await decryptMessage(encryptedReceiverRandomString, receiver.privateKey)
  );

	const receiverHash = await poseidonHash(decryptedReceiverKey.receiverRandomString);

  console.log("Receiver hash: ", receiverHash);

  const messages = JSON.parse((await ethMail.getMessages(receiverHash))[0]);

  const senderPublicKey = (
    await ethMail.lookup(decryptedReceiverKey.receiver)
  )[1];
  const senderPublicKeyDecoded = ethers.utils.defaultAbiCoder.decode(
    ["string"],
    senderPublicKey
  )[0];

	const sharedKey = computeSharedKey(receiver, senderPublicKeyDecoded);
  const decryptedMessage = aesDecrypt(
    messages,
    sharedKey
  );
  // console.log(decryptedMessage)

  return decryptedMessage;
}

async function registerDomain(signer, ethMail, domain, encodedPublicKey) {
    const tx = await ethMail.connect(signer).registerDomain(domain, encodedPublicKey);
    await tx.wait();
    console.log("Domain registered");
    return tx.hash;
}

function decryptAllMessages(sharedKey, messages) {
	const decryptedMessages = messages.map((message) => {
		const decryptedMessage = aesDecrypt(
			JSON.parse(message),
			sharedKey
		);
		return JSON.parse(decryptedMessage);
	});
	return decryptedMessages;
}

async function getAllUserHandshakes(receiver, ethMail) {
	const [filter1, filter2] = [
		ethMail.filters.HandshakeCompleted(receiver.address, null),
		ethMail.filters.HandshakeCompleted(null, receiver.address)
	];
	const [senderHandshakesEvents, receiverHandshakesEvent] = await Promise.all([
		ethMail.queryFilter(filter1),
		ethMail.queryFilter(filter2)
	]);
	
	const senderAddresses = senderHandshakesEvents.map((event) => {
		return event.args[1];
	});
	const receiverAddresses = receiverHandshakesEvent.map((event) => {
		return event.args[0];
	});
	const allAddresses = [...senderAddresses, ...receiverAddresses];

	const allEthMail = await Promise.all(
		allAddresses.map(async (address) => {
			const domain = await ethMail.getDomainByOwner(address);
			return domain;
		}));

	return allEthMail;
}

async function checkAllMessagesForSender(receiver, senderEthMail, ethMail) {

	const senderLookup = await ethMail.lookup(senderEthMail);
	const senderAddress = senderLookup[0];
	const senderPublicKey = senderLookup[1];

  const receiverHandshake = await ethMail.getHandshakes(receiver.address, senderAddress);

	console.log("receiverHandshake:", receiverHandshake)
  const encryptedReceiverRandomString = JSON.parse(
    ethers.utils.toUtf8String(receiverHandshake)
  );
  console.log(encryptedReceiverRandomString);

  const decryptedReceiverKey = JSON.parse(
    await decryptMessage(encryptedReceiverRandomString, receiver.privateKey)
  );

	const decryptedSenderRandomString = decryptedReceiverKey.senderRandomString;
	const decryptedReceiverRandomString = decryptedReceiverKey.receiverRandomString;

	const [senderHash, receiverHash] = await Promise.all([
		poseidonHash(decryptedSenderRandomString),
		poseidonHash(decryptedReceiverRandomString)
	]);

	const sentMessages = await ethMail.getMessages(senderHash);
	const receivedMessages = await ethMail.getMessages(receiverHash);


  const senderPublicKeyDecoded = ethers.utils.defaultAbiCoder.decode(
    ["string"],
    senderPublicKey
  )[0];

	const sharedKey = computeSharedKey(receiver, senderPublicKeyDecoded);

	const [decryptedSentMessages, decryptedReceivedMessages] = await Promise.all([
		decryptAllMessages(sharedKey, sentMessages),
		decryptAllMessages(sharedKey, receivedMessages)
	]);

	console.log(decryptedSentMessages, decryptedReceivedMessages)

	return [decryptedSentMessages, decryptedReceivedMessages];

}
function createECDHIdentity() {
  const alice = crypto.createECDH("secp256k1");
  alice.generateKeys();

  // Get public and private keys in hex format
  const publicKey = alice.getPublicKey("hex");
  const privateKey = alice.getPrivateKey("hex");

  const address = EthCrypto.publicKey.toAddress(publicKey);

  const signer = new ethers.Wallet(privateKey, ethers.provider);

  return {
    address: address,
    privateKey: privateKey,
    publicKey: publicKey,
    signer: signer,
  };
}

async function createIdentity() {
  
  const sender = createECDHIdentity();
  const receiver = createECDHIdentity();

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

  return { sender, receiver, senderWallet, receiverWallet };
}


module.exports = {
    deployContracts,
    createIdentity,
    registerDomain,
    createHandshake,
    completeHandshake,
    sendMessage,
    checkMessages,
    verifyMessage,
    mineBlocks,
		checkAllMessagesForSender,
		getAllUserHandshakes,
}