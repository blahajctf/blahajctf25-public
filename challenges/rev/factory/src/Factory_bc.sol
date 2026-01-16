//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

interface IFlag {
    function flag() external returns (string memory);
}

contract Factory {

    bytes public flagBytecode;
    address public flag_contract;

    constructor(bytes memory _bytecode) {
        flagBytecode = _bytecode;
    }

    function make(string memory _f) public returns (address) {
        bytes memory data = hex"c52b2cbc9254c72e657858e2fe17ab5e0d97dda00535d21bef4a217b";
        bytes memory constructorArgs = abi.encode(_f, data);
        bytes memory fullBytecode = abi.encodePacked(flagBytecode, constructorArgs);

        address deployedAddress;

        assembly {
            deployedAddress := create(0, add(fullBytecode, 0x20), mload(fullBytecode))
        }

        require(deployedAddress != address(0), "Deployment failed");
        flag_contract = deployedAddress;
        return deployedAddress;
    }

    function flag() public returns(string memory){
        return IFlag(flag_contract).flag();
    }
}