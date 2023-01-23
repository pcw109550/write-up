// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "./Solution.sol";

contract Factory {
    Solution public solution;

    function deploy() public {
        solution = new Solution{salt: "pcw109550"}();
    }
}
