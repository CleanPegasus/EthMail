const { hardhat, ethers } = require("hardhat");

const { deployContracts } = require("./utils");

deployContracts().then((contracts) => {
    console.log(contracts.address);
});