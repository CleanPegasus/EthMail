// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

// import './verifier.sol';
import './IVerifier.sol';

contract EthMail {

    struct Domain {
        address owner;
        string publicKey;
        mapping (address => bytes) handshakes;
    }

    struct lastMessage {
        bytes32 hash;
        uint256 timestamp;
    }

    mapping (bytes => Domain) domains;
    mapping (address => bytes) domainsByOwner;
    mapping (bytes32 => string[]) messages;
    mapping (bytes32 => lastMessage) lastMessageHash;
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

    function registerDomain(string memory domain, string memory publickey) isEthMail(domain) external {
        bytes memory domainBytes = bytes(domain);
        require(domains[domainBytes].owner == address(0), "Domain already registered");
        domains[domainBytes].owner = msg.sender;
        domains[domainBytes].publicKey = publickey;
        domainsByOwner[msg.sender] = bytes(domain);
        emit DomainRegistered(domain, msg.sender, publickey);
    }

    function lookup(string memory domain) external view returns (address owner, string memory publicKey) {
        bytes memory domainBytes = bytes(domain);
        return (domains[domainBytes].owner, domains[domainBytes].publicKey);
    }

    function createHandshake(string memory domainName, address receiver, bytes memory senderEncryptedRandomStrings, 
                            bytes memory receiverEncryptedRandomStrings) external {
        
        bytes memory domainBytes = bytes(domainName);
        address owner = domains[domainBytes].owner;
        require(owner == msg.sender, "Only the domain owner can create a handshake");

        domains[domainBytes].handshakes[receiver] = senderEncryptedRandomStrings;
        addUser[receiver].push(receiverEncryptedRandomStrings);
        
        // Emit an event
        emit HandshakeCreated(msg.sender, receiver);
    }

    function completeHandshake(string memory domainName, address sender, bytes memory receiverEncryptedRandomStrings) external {

        bytes memory domainBytes = bytes(domainName);
        address owner = domains[domainBytes].owner;
        require(owner == msg.sender, "Only the domain owner can complete a handshake");
        domains[domainBytes].handshakes[sender] = receiverEncryptedRandomStrings;

        // Emit an event
        emit HandshakeCompleted(sender, msg.sender);

    }

    function sendMessage(string memory encryptedMsg, bytes32 lastMsgHash, 
                        uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[3] calldata _pubSignals ) external {

        // ZK Proof to check the sender knows the random string X with the zkProof and senderHash
        bool verification = verifier.verifyProof(_pA, _pB, _pC, _pubSignals);
        require(verification, "Invalid proof");
        require(nonce[msg.sender] == _pubSignals[0], "Invalid nonce");

        bytes32 senderHash = bytes32(_pubSignals[1]);
        // Push the message to the mapping for a senderHash
        messages[senderHash].push(encryptedMsg);
        // Add a mapping that stores the hash last encypted message + timestamp in a mapping for a senderHash
        lastMessageHash[senderHash] = lastMessage(lastMsgHash, block.timestamp);
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

    function getDomainByOwner(address user) public view returns (string memory) {
        return string(domainsByOwner[user]);
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
