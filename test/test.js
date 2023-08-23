const { hardhat, ethers } = require("hardhat");
const {
  loadFixture,
} = require("@nomicfoundation/hardhat-toolbox");
const utils = require('../scripts/utils');
const { expect } = require("chai");

const crypto = require("crypto");
const EthCrypto = require("eth-crypto");

/**
 * 1. Deploy the contracts
 * 2. Create a new account
 * 3. Create Handshake
 * 4. Complete Handshake
 * 5. Send Message
 * 6. Receive Message
 * 7. Verify Message
 */

describe("EthMail", function () {
  // let sender, receiver, account;

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
  
  async function createIdentityFixtures() {
    
    const sender = createECDHIdentity();
    const receiver = createECDHIdentity();

    console.log("Reached here")
  
    const senderWallet = new ethers.Wallet(sender.privateKey, ethers.provider);
    const receiverWallet = new ethers.Wallet(receiver.privateKey, ethers.provider);
    
    console.log("Reached here 1")
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

    console.log("Reached here 2")
  
    return { sender, receiver, senderWallet, receiverWallet };
  }
  
  describe("Deployment", function () {
    it("Should be able to deploy the contracts", async function () {
      const ethMail = await utils.deployContracts();
      expect(ethMail).to.not.be.null;
    });
  });

  describe("Tests", function () {
    it("Should be able to create an account", async function () {
      const ethMail = await utils.deployContracts();
      const {sender, receiver, senderWallet, receiverWallet} = await createIdentityFixtures();
      const encodedSenderPublicKey = ethers.utils.defaultAbiCoder.encode(
        ["string"],
        [sender.publicKey]
      );
      const senderTx = await utils.registerDomain(senderWallet, ethMail, 'sender.ethMail', encodedSenderPublicKey);
      expect(senderTx).to.not.be.null;
      const encodedReceiverPublicKey = ethers.utils.defaultAbiCoder.encode(
        ["string"],
        [receiver.publicKey]
      );
      const receiverTx = await utils.registerDomain(receiverWallet, ethMail, 'receiver.ethMail', encodedReceiverPublicKey);
      expect(receiverTx).to.not.be.null;

      this.sender = sender;
      this.receiver = receiver;
      this.senderWallet = senderWallet;
      this.receiverWallet = receiverWallet;
      this.ethMail = ethMail;

    });

    it("Should be able to create a handshake", async function () {
      const {sender, receiver, senderWallet, receiverWallet, ethMail} = this;
      const handshake = await utils.createHandshake(sender, 'sender.ethMail', senderWallet, 'receiver.ethMail', ethMail);
      expect(handshake).to.not.be.null;
    });

    it("Should be able to complete a handshake", async function () {
      const {sender, receiver, senderWallet, receiverWallet, ethMail} = this;
      const handshake = await utils.completeHandshake(receiver, 'receiver.ethMail', receiverWallet, ethMail, 0);
      expect(handshake).to.not.be.null;
    });

    it("Should be able to send a message", async function () {
      const {sender, receiver, senderWallet, receiverWallet, ethMail} = this;
      const message = "Hello World";
      const tx = await utils.sendMessage(sender, senderWallet, 'receiver.ethMail', message, ethMail);
      expect(tx).to.not.be.null;
    });

    it("Should be able to receive a message", async function () {
      const {sender, receiver, senderWallet, receiverWallet, ethMail} = this;
      const decryptedMessage = await utils.checkMessages(receiver, 'sender.ethMail', ethMail);
      expect(decryptedMessage).to.not.be.null;
      this.decryptedMessage = decryptedMessage;
    });

    it("Should be able to verify a message", async function () {
      const {sender, receiver, senderWallet, receiverWallet, ethMail, decryptedMessage} = this;
      const verified = await utils.verifyMessage(decryptedMessage, senderWallet.address);
      expect(verified).to.be.true;
    });
  });


});
