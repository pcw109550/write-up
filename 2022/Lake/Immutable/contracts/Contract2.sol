// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

contract Contract2 {
    constructor(bytes memory code) {
        assembly {
            return (add(code, 0x20), mload(code))
        }
    }
}
