const { hardhat, ethers } = require("hardhat");
const EthCrypto = require("eth-crypto");
const snarkjs = require("snarkjs");
const circomlibjs = require("circomlibjs");

const crypto = require("crypto");

const utils = require("./utils");

// const eccrypto = require("eccrypto");

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
	console.log(ethers.provider)
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


async function main() {
  // deploy EthMail contract
  const ethMail = await utils.deployContracts();

  // create sender and receiver identities
  const { sender, receiver, senderWallet, receiverWallet } = await createIdentity();

  const senderEthMail = "sender.ethMail";
  const receiverEthMail = "receiver.ethMail";

  // register sender and receiver domains
  const encodedSenderPublicKey = ethers.utils.defaultAbiCoder.encode(
    ["string"],
    [sender.publicKey]
  );
  await ethMail.connect(senderWallet).registerDomain(senderEthMail, encodedSenderPublicKey);

  const encodedReceiverPublicKey = ethers.utils.defaultAbiCoder.encode(
    ["string"],
    [receiver.publicKey]
  );
  await ethMail.connect(receiverWallet).registerDomain(receiverEthMail, encodedReceiverPublicKey);

  // create handshake
  await utils.createHandshake(sender, senderEthMail, senderWallet, receiverEthMail, ethMail);

  console.log("Handshake created");

  // Complete handshake
  await utils.completeHandshake(receiver, receiverEthMail, receiverWallet, ethMail, 0);
  console.log("Handshake completed");

  utils.mineBlocks(10);

  // Send message from sender to receiver
  const message = "Hello World";

  await utils.sendMessage(sender, senderWallet, receiverEthMail, message, ethMail);

  utils.mineBlocks(10);

  await utils.sendMessage(sender, senderWallet, receiverEthMail, message, ethMail);

  utils.mineBlocks(10);

  await utils.sendMessage(receiver, receiverWallet, senderEthMail, message, ethMail);

  const decryptedMessage = await utils.checkMessages(receiver, senderEthMail, ethMail);
	// verify the message
	console.log(JSON.parse(decryptedMessage).message.message);
	const verified = await utils.verifyMessage(decryptedMessage, senderWallet.address);
	console.log("Message verified: ", verified)

  await utils.checkAllMessagesForSender(receiver, senderEthMail, ethMail);

  const allEthMails = await utils.getAllUserHandshakes(receiver, ethMail);
  console.log(allEthMails);
  
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
