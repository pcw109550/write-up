// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

contract Attack {
    event Result(address addr, bytes bytecode);

    function deployBytecode(bytes memory bytecode) public returns (address) {
        address addr;
        uint256 length = bytecode.length;
        /*
            NOTE: How to call create

            create(v, p, n)
            create new contract with code at memory p to p + n
            and send v wei
            and return the new address
        */
        assembly {
            addr := create(
                0,                   // 0 wei sent
                add(bytecode, 0x20), // ignore offset data. Can be hardcode to 0xa0 
                length               // bytecode length
            )
        }
        emit Result(addr, addr.code);
        return addr;
   }
}
