// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

contract Contract1 {
    function destruct() public {
        selfdestruct(payable(0));
    }
}
