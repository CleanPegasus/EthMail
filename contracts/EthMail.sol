// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import 'hardhat/console.sol';
// import './verifier.sol';
import './IVerifier.sol';

contract EthMail {

    struct Domain {
        address owner;
        string publicKey;
    }

    mapping (string => Domain) domains;
    mapping (bytes32 => string[]) messages;
    mapping (bytes32 => bytes32) lastMessageHash;
    mapping (address => bytes[]) handshakes;
    mapping (address => bytes[]) addUser;
    mapping (address => uint256) nonce;

    event DomainRegistered(string domain, address owner, string publicKey);
    event DomainUpdated(string domain, address owner, string publicKey);

    IVerifier verifier;

    constructor(address _verifier) {
        verifier = IVerifier(_verifier);
    }

    function registerDomain(string memory domain, string memory publickey) public {
        require(domains[domain].owner == address(0), "Domain already registered");

        domains[domain] = Domain(msg.sender, publickey);
        emit DomainRegistered(domain, msg.sender, publickey);
    }

    function lookup(string memory domain) public view returns (address owner, string memory publicKey) {
        Domain memory domainInfo = domains[domain];
        return (domainInfo.owner, domainInfo.publicKey);
    }

    function createHandshake(address receiver, bytes memory encryptedRandomString) public {
        // TODO: Checks
        addUser[receiver].push(encryptedRandomString);
        // TODO: Emit an event
    }

    function completeHandshake(address sender, 
                            bytes memory receiverEncryptedRandomStrings, 
                            bytes memory senderEncryptedRandomStrings) external {
        // TODO: ZK Proof to check the sender knows the random string X with the zkProof and senderHash

        // console.log(sender);
        handshakes[sender].push(senderEncryptedRandomStrings);
        handshakes[msg.sender].push(receiverEncryptedRandomStrings);


        // TODO: Emit an event
    }

    function sendMessage(string memory encryptedMsg, bytes32 lastMsgHash, 
                        uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[3] calldata _pubSignals ) external {

        // ZK Proof to check the sender knows the random string X with the zkProof and senderHash
        bool verification = verifier.verifyProof(_pA, _pB, _pC, _pubSignals);
        require(verification, "Invalid proof");
        require(nonce[msg.sender] == _pubSignals[0], "Invalid nonce");

        bytes32 senderHash = bytes32(_pubSignals[1]);

        messages[senderHash].push(encryptedMsg);

        // TODO: Add a mapping that stores the hash last encypted message + timestamp in a mapping for a senderHash
        lastMessageHash[senderHash] = lastMsgHash;

        // Increment the nonce
        nonce[msg.sender] = nonce[msg.sender] + 1;
        // TODO: Emit an event
    }

    function getMessages(uint256 senderHash) public view returns (string[] memory) {
        return messages[bytes32(senderHash)];
    }

    function getAddedUsers(address user) public view returns (bytes[] memory) {
        return addUser[user];
    }

    function getHandshakes(address user) public view returns (bytes[] memory) {
        return handshakes[user];
    }

    function getNonce(address user) public view returns (uint256) {
        return nonce[user];
    }

}
