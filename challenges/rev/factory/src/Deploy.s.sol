// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import { Factory } from "../src/Factory_bc.sol"; 

contract DeployFactory is Script {
    function run() external {
        string memory bytecodeString = vm.readFile("Flag.bin");
        bytes memory flagBytecode = vm.parseBytes(bytecodeString);

        bytes memory deploymentBytecode = abi.encodePacked(
            type(Factory).creationCode, 
            abi.encode(flagBytecode)
        );

        vm.writeFile("Factory_Deployment.hex", vm.toString(deploymentBytecode));

        console.log("--------------------------------------------------");
        console.log("Challenge artifact generated: Factory_Deployment.hex");
        console.log("--------------------------------------------------");
        
        vm.startBroadcast();
        Factory factory = new Factory(flagBytecode);
        factory.make("2XcLHm}");
        factory.flag();
        vm.stopBroadcast();
    }
}