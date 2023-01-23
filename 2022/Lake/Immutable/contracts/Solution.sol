// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "./Contract1.sol";
import "./Contract2.sol";

contract Solution {
    Contract1 public contract1;
    Contract2 public contract2;

    function deploy1() public {
        contract1 = new Contract1();    
    }

    function deploy2(bytes memory code) public {
        contract2 = new Contract2(code);
    }

    function destruct() public {
        contract1.destruct();
        selfdestruct(payable(0));
    }
}
