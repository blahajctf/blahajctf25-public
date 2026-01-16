//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

event FlagRevealed(string flagString);

contract Hasher {
    constructor(bytes memory data) {
        bytes32 h = keccak256(data);
        assembly {
            mstore(0x00, h)
            return(0x00, 32)
        }
    }
}

contract Flag {
    string private key;
    bytes private ct;

    constructor(string memory _key, bytes memory _ct) {
        key = _key;
        ct = _ct;
    }

    function obfuscatedKeccak(bytes memory data) public returns (bytes32 hash) {
        Hasher temp = new Hasher(data);
        address target = address(temp);

        assembly {
            if iszero(extcodesize(target)) {
                revert(0, 0)
            }
            extcodecopy(target, 0x00, 0, 32)
            hash := mload(0x00)
        }

        return hash;
    }

    function flag() public returns (string memory) {
        if (keccak256(bytes(key)) == obfuscatedKeccak(bytes("2XcLHm}"))) {
            bytes memory c = new bytes(ct.length);
            bytes memory b = abi.encodePacked(keccak256(bytes(key)));
            for (uint256 i = 0; i < ct.length; i++) {
                uint256 j = i % b.length;
                c[i] = bytes1(uint8((uint8(ct[i]) + 256 - uint8(b[j])) % 256));
            }
            string memory result = string(c);
            emit FlagRevealed(result); 
            return result;
        } else {
            emit FlagRevealed("not the flag vro");
            return "not the flag vro";
        }
    }
}
