const { hardhat, ethers } = require("hardhat");
const EthCrypto = require("eth-crypto");
const snarkjs = require("snarkjs");
const circomlibjs = require("circomlibjs");
const secp256k1 = require("secp256k1");
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

async function computeSharedKey(sender, receiverPublicKey) {
  const dhke = crypto.createECDH("secp256k1");
  dhke.setPrivateKey(sender.privateKey, "hex");
  const sharedKey = dhke.computeSecret(receiverPublicKey, "hex");
  return sharedKey;
}

function computeSharedKey(sender, receiverPublicKey) {
  const dhke = crypto.createECDH("secp256k1");
  dhke.setPrivateKey(sender.privateKey, "hex");
  const sharedKey = dhke.computeSecret(receiverPublicKey, "hex");
  return sharedKey;
}

function aesEncrypt(message, sender, receiverPublicKey) {
  const sharedKey = computeSharedKey(sender, receiverPublicKey);

  const iv = crypto.randomBytes(16); // Random initialization vector
  console.log("iv", iv);
  const cipher = crypto.createCipheriv(
    "aes-256-cbc",
    sharedKey.slice(0, 32),
    iv
  ); // Use only the first 32 bytes as the key
  let encrypted = cipher.update(message, "utf8", "hex");
  encrypted += cipher.final("hex");

  return { iv, encrypted };
}

function aesDecrypt(encryptedMessage, receiver, SenderPublicKey) {
  const sharedKey = computeSharedKey(receiver, SenderPublicKey);
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

function createECDHIdentity() {
  const alice = crypto.createECDH("secp256k1");
  alice.generateKeys();

  // Get public and private keys in hex format
  const publicKey = alice.getPublicKey("hex");
  const privateKey = alice.getPrivateKey("hex");

  const address = EthCrypto.publicKey.toAddress(publicKey);

  return {
    address: address,
    privateKey: privateKey,
    publicKey: publicKey,
  };
}

async function createIdentity() {
  const sender = createECDHIdentity();
  const receiver = createECDHIdentity();

  const senderWallet = new ethers.Wallet(sender.privateKey, ethers.provider);
  const receiverWallet = new ethers.Wallet(
    receiver.privateKey,
    ethers.provider
  );

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
    receiver: "receiver.ethmail",
    senderRandomString: senderRandomString,
    receiverRandomString: receiverRandomString,
  };

  const encodedSenderHandshakeRandomStrings = JSON.stringify(
    senderHandshakeRandomStrings
  );

  const receiverHandshakeRandomStrings = {
    receiver: "sender.ethmail",
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
      receiverAddress,
      encryptedSenderRandomHexs,
      encryptedReceiverRandomHexes
    );
  await tx.wait();

  return tx.hash;
}

async function completeHandshake(receiver, receiverWallet, ethMail) {
  const receiverEncryptedRandomStrings = (
    await ethMail.getAddedUsers(receiverWallet.address)
  )[0];

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

  // Complete the handshake
  const tx = await ethMail
    .connect(receiverWallet)
    .completeHandshake(receiverEncryptedRandomStrings);
  await tx.wait();

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

async function sendMessage(
  sender,
  senderWallet,
  receiverEthMail,
  message,
  ethMail
) {
  const receiverPublicKey = (await ethMail.lookup(receiverEthMail))[1];
  console.log("receiverPublicKey:", receiverPublicKey);
  const receiverPublicKeyDecoded = ethers.utils.defaultAbiCoder.decode(
    ["string"],
    receiverPublicKey
  )[0];

  const encryptedMessage = JSON.stringify(
    aesEncrypt(message, sender, receiverPublicKeyDecoded)
  );

  const senderHandshakes = await ethMail.getHandshakes(senderWallet.address);
  // console.log(senderWallet.address)
  console.log(senderHandshakes);

  const encryptedSenderRandomString = JSON.parse(
    ethers.utils.toUtf8String(senderHandshakes[0])
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

async function checkMessages(receiver, ethMail) {
  const receiverHandshakes = await ethMail.getHandshakes(receiver.address);

  const encryptedReceiverRandomString = JSON.parse(
    ethers.utils.toUtf8String(receiverHandshakes[0])
  );
  console.log(encryptedReceiverRandomString);

  const decryptedReceiverKey = JSON.parse(
    await decryptMessage(encryptedReceiverRandomString, receiver.privateKey)
  );
  console.log(decryptedReceiverKey.receiverRandomString);

  // const receiverHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(decryptedReceiverKey.receiverRandomString));

  const poseidon = await circomlibjs.buildPoseidon();
  const receiverHash = poseidon.F.toString(
    poseidon([BigInt(decryptedReceiverKey.receiverRandomString)])
  );

  console.log("Receiver hash: ", receiverHash);

  const messages = JSON.parse((await ethMail.getMessages(receiverHash))[0]);

  const senderPublicKey = (
    await ethMail.lookup(decryptedReceiverKey.receiver)
  )[1];
  const senderPublicKeyDecoded = ethers.utils.defaultAbiCoder.decode(
    ["string"],
    senderPublicKey
  )[0];
  const decryptedMessage = aesDecrypt(
    messages,
    receiver,
    senderPublicKeyDecoded
  );
  // console.log(decryptedMessage)

  return decryptedMessage;
}

async function main() {
  // deploy EthMail contract
  const ethMail = await deployContracts();

  // create sender and receiver identities
  const { sender, receiver, senderWallet, receiverWallet } =
    await createIdentity();
  const senderEthMail = "sender.ethmail";
  const receiverEthMail = "receiver.ethmail";

  // register sender and receiver domains
  const encodedSenderPublicKey = ethers.utils.defaultAbiCoder.encode(
    ["string"],
    [sender.publicKey]
  );
  await ethMail
    .connect(senderWallet)
    .registerDomain(senderEthMail, encodedSenderPublicKey);

  const encodedReceiverPublicKey = ethers.utils.defaultAbiCoder.encode(
    ["string"],
    [receiver.publicKey]
  );
  await ethMail
    .connect(receiverWallet)
    .registerDomain(receiverEthMail, encodedReceiverPublicKey);

  // create handshake
  const { senderRandomString, receiverRandomString } = await createHandshake(
    sender,
    senderWallet,
    receiverEthMail,
    ethMail
  );

  console.log("Handshake created");

  // Complete handshake
  await completeHandshake(receiver, receiverWallet, ethMail);
  console.log("Handshake completed");

  mineBlocks(100);

  // Send message from sender to receiver
  const message = "Hello World";

  await sendMessage(sender, senderWallet, receiverEthMail, message, ethMail);

  mineBlocks(100);

  const decryptedMessage = await checkMessages(receiver, ethMail);
  console.log(decryptedMessage);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

// async function test() {

// 	// create sender and receiver identities
// 	const { sender, receiver, senderWallet, receiverWallet } = await createIdentity();

// 	console.log(sender.privateKey)
// 	console.log(receiver.publicKey)

// 	dhkeEncrypt(sender, receiver);

// }

// test()
