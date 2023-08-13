// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import 'hardhat/console.sol';
// import './verifier.sol';
import './IVerifier.sol';

contract EthMail {

    struct Domain {
        address owner;
        string publicKey;
        mapping (address => bytes) handshakes;
    }

    mapping (string => Domain) domains;
    mapping (address => string) domainsByOwner;
    mapping (bytes32 => string[]) messages;
    mapping (bytes32 => bytes32) lastMessageHash;
    mapping (address => bytes[]) addUser;
    mapping (address => uint256) nonce;

    event DomainRegistered(string domain, address owner, string publicKey);
    event DomainUpdated(string domain, address owner, string publicKey);

    event HandshakeCreated(address indexed sender, address indexed receiver);

    event HandshakeCompleted(address indexed sender, address indexed receiver);

    IVerifier verifier;

    constructor(address _verifier) {
        verifier = IVerifier(_verifier);
    }

    function registerDomain(string memory domain, string memory publickey) isEthMail(domain) public {
        require(domains[domain].owner == address(0), "Domain already registered");
        require(ifEthMail(domain), "Domain name must end with .ethMail");
        domains[domain].owner = msg.sender;
        domains[domain].publicKey = publickey;
        domainsByOwner[msg.sender] = domain;
        emit DomainRegistered(domain, msg.sender, publickey);
    }

    function lookup(string memory domain) public view returns (address owner, string memory publicKey) {
        return (domains[domain].owner, domains[domain].publicKey);
    }

    function createHandshake(string memory domainName, address receiver, bytes memory senderEncryptedRandomStrings, 
                            bytes memory receiverEncryptedRandomStrings) public {

        address owner = domains[domainName].owner;
        require(owner == msg.sender, "Only the domain owner can create a handshake");

        domains[domainName].handshakes[receiver] = senderEncryptedRandomStrings;
        addUser[receiver].push(receiverEncryptedRandomStrings);
        
        // TODO: Emit an event
        emit HandshakeCreated(msg.sender, receiver);
    }

    function completeHandshake(string memory domainName, address sender, bytes memory receiverEncryptedRandomStrings) external {

        address owner = domains[domainName].owner;
        require(owner == msg.sender, "Only the domain owner can complete a handshake");
        domains[domainName].handshakes[sender] = receiverEncryptedRandomStrings;

        // TODO: Emit an event
        emit HandshakeCompleted(sender, msg.sender);

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

    function getHandshakes(address user, address reciever) public view returns (bytes memory) {
        return domains[domainsByOwner[user]].handshakes[reciever];
    }

    function getNonce(address user) public view returns (uint256) {
        return nonce[user];
    }

    modifier isEthMail(string memory domain) {
        require(ifEthMail(domain), "Domain name must end with .ethMail");
        _;
    }

    function ifEthMail(string memory input) public pure returns (bool) {
        bytes memory inputBytes = bytes(input);
        bytes memory ethMailBytes = bytes(".ethMail");
        
        if(inputBytes.length < 8) {
            return false;
        }
        
        for(uint i = 0; i < 8; i++) {
            if(inputBytes[inputBytes.length - 8 + i] != ethMailBytes[i]) {
                return false;
            }
        }
        
        return true;
    }

}
