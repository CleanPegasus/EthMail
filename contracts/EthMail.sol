// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import 'hardhat/console.sol';

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

    event DomainRegistered(string domain, address owner, string publicKey);
    event DomainUpdated(string domain, address owner, string publicKey);

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

        console.log(sender);
        handshakes[sender].push(senderEncryptedRandomStrings);
        handshakes[msg.sender].push(receiverEncryptedRandomStrings);


        // TODO: Emit an event
    }

    function sendMessage(string memory encryptedMsg, bytes32 senderHash, bytes32 lastMsgHash /*, bytes32 msgHash, bytes32 zkProof */) public {

        // TODO: ZK Proof to check the sender knows the random string X with the zkProof and senderHash

        messages[senderHash].push(encryptedMsg);

        // TODO: Add a mapping that stores the hash last encypted message + timestamp in a mapping for a senderHash
        lastMessageHash[senderHash] = lastMsgHash;
        // TODO: Emit an event
    }

    function getMessages(bytes32 senderHash) public view returns (string[] memory) {
        return messages[senderHash];
    }

    function getAddedUsers(address user) public view returns (bytes[] memory) {
        return addUser[user];
    }

    function getHandshakes(address user) public view returns (bytes[] memory) {
        return handshakes[user];
    }

}
