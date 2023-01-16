// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

// These files are dynamically created at test time
import "truffle/Assert.sol";
import "truffle/DeployedAddresses.sol";
import "../contracts/Attack.sol";

contract TestAttack {
    function testAttack() public {
        Attack attack = Attack(DeployedAddresses.Attack());

        bytes memory bytecode = hex"383434393834F3";
        require(bytecode.length < 8, "BYTECODE_LENGTH_TOO_LONG");
        /*
            len(bytecode) == 7

            38: CODESIZE     // 7
            34: CALLVALUE    // 0 
            34: CALLVALUE    // 0
            39: CODECOPY     // memory[0:7] = address(this).code[0:7]
            38: CODESIZE     // 7
            34: CALLVALUE    // 0
            F3: RETURN       // return memory[0:7]
        */
        
        address addr = attack.deployBytecode(bytecode);
        bytes memory bytecode_deployed = addr.code;

        Assert.equal(keccak256(bytecode), keccak256(bytecode_deployed), "bytecode mismatch");
    }
}
