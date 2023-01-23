// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "truffle/Assert.sol";
import "truffle/DeployedAddresses.sol";
import "../contracts/Factory.sol";
import "../contracts/Solution.sol";
import "../contracts/Contract1.sol";
import "../contracts/Contract2.sol";

contract TestSolution {
    Factory factory;
    bytes bytecode_before;
    Contract1 contract_before;

    event Result(address addr);
    event Bytecode(bytes bytecode_before, bytes bytecode_after);

    function test_step1() public {
        factory = new Factory();
        factory.deploy();

        Solution solution_before = factory.solution(); 
        solution_before.deploy1();
        
        contract_before = solution_before.contract1();

        emit Result(address(contract_before));

        bytecode_before = address(contract_before).code;

        solution_before.destruct();
    }

    function test_step2() public {
        // assuming that test_step1() is executed first
        factory.deploy();

        bytes memory dummy = hex"13371337";
        Solution solution_after = factory.solution();
        solution_after.deploy2(dummy);

        Contract2 contract_after = solution_after.contract2();

        bytes memory bytecode_after = address(contract_after).code;

        require(keccak256(dummy) == keccak256(bytecode_after), "sanity check");

        Assert.equal(address(contract_before), address(contract_after), "address mismatch");
        Assert.notEqual(keccak256(bytecode_before), keccak256(bytecode_after), "bytecode match");

        emit Bytecode(bytecode_before, bytecode_after);
    }
}
