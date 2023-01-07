// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.0;

contract Challenge {
    uint256 public p = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    bool public solved = false;
    bool public solved1 = false;
    bool public solved2 = false;
    bool public solved3 = false;

    function isPowerOf2(uint256 n) public pure returns (bool) {
        while(n % 2 == 0) {
            n = n / 2;
        }
        return n == 1;
    }

    function declareSolved() public {
        if(solved1 == true && solved2 == true && solved3 == true) {
            solved = true;
        }
    }

    function sanity_check(uint256 n, uint256[] memory f, uint256[] memory t, uint256[] memory s1, uint256[] memory s2) internal returns (bool) {
        require(isPowerOf2(n + 1), "n + 1 not power of 2");
        require(f.length == n && t.length == n + 1 && s1.length == n + 1 && s2.length == n + 1, "length checks");
        for(uint i = 0 ; i < f.length ; i++) {
            require(0 <= f[i] && f[i] < p);
        }
        for(uint i = 0 ; i < t.length ; i++) {
            require(0 <= t[i] && t[i] < p);
        }
        for(uint i = 0 ; i < s1.length ; i++) {
            require(0 <= s1[i] && s1[i] < p);
        }
        for(uint i = 0 ; i < s2.length ; i++) {
            require(0 <= s2[i] && s2[i] < p);
        }
        return true;
    }

    function final_check(uint256 n, uint256[] memory f, uint256[] memory t, uint256[] memory s1, uint256[] memory s2, uint256 beta, uint256 gamma) internal view returns (bool) {
        uint256 LHS = 1;
        for(uint i = 0 ; i < n ; i++) {
            LHS = mulmod(LHS, 1 + beta, p);
            uint256 mul = (mulmod(gamma, 1 + beta, p) + mulmod(beta, t[i + 1], p) + t[i]) % p;
            LHS = mulmod(LHS, mulmod(mul, gamma + f[i], p), p);
        }
        uint256 RHS = 1;
        for(uint i = 0 ; i < n ; i++) {
            uint256 mul1 = (mulmod(gamma, 1 + beta, p) + mulmod(beta, s1[i + 1], p) + s1[i]) % p;
            uint256 mul2 = (mulmod(gamma, 1 + beta, p) + mulmod(beta, s2[i + 1], p) + s2[i]) % p;
            RHS = mulmod(RHS, mulmod(mul1, mul2, p), p);
        }
        require(LHS == RHS, "check failed");

        for(uint i = 0 ; i < n ; i++) {
            bool ex = false;
            for(uint j = 0 ; j <= n ; j++) {
                if(f[i] == t[j]) {
                    ex = true;
                }
            }
            if(ex == false) return true;
        }
        return false;
    }

    function challenge1(uint256 n, uint256[] memory f, uint256[] memory t, uint256[] memory s1, uint256[] memory s2) public {
        require(sanity_check(n, f, t, s1, s2), "sanity check failed");
        bytes32 beta = keccak256(abi.encode(n, f, t, s1, s2, uint256(1)));
        bytes32 gamma = keccak256(abi.encode(n, f, t, s1, s2, uint256(2)));
        require(final_check(n, f, t, s1, s2, uint256(beta) % p, uint256(gamma) % p), "final check failed");
        solved1 = true;
    }

   function challenge2(uint256 n, uint256[] memory f, uint256[] memory t, uint256[] memory s1, uint256[] memory s2) public {
        require(sanity_check(n, f, t, s1, s2), "sanity check failed");
        uint256 len = (12 + 4 * n) * 0x20;
        bytes32 beta; bytes32 gamma;
        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, 4, len)
            mstore(add(ptr, len), 1)
            beta := keccak256(ptr, add(len, 32))
            mstore(add(ptr, len), 2)
            gamma := keccak256(ptr, add(len, 32))
        }
        
        require(final_check(n, f, t, s1, s2, uint256(beta) % p, uint256(gamma) % p), "final check failed");
        require(s1[n] == s2[0], "middle equality check failed");
        solved2 = true;
    }

  function challenge3(uint256 n, uint256[] memory f, uint256[] memory t, uint256[] memory s1, uint256[] memory s2) public {
        bytes32 beta; bytes32 gamma;
        for(uint i = 0 ; i < 4 * n + 7 ; i++) {
            assembly {
                let ptr := mload(0x40)
                mstore(ptr, beta)
                mstore(add(ptr, 32), gamma)
                mstore(add(ptr, 64), mload(add(0x80, mul(i, 32))))
                mstore8(add(ptr, 96), 1)
                mstore8(add(ptr, 97), 2)
                beta := keccak256(ptr, 97)
                gamma := keccak256(ptr, 98)
            }
        }
        require(sanity_check(n, f, t, s1, s2), "sanity check failed");    
        require(final_check(n, f, t, s1, s2, uint256(beta) % p, uint256(gamma) % p), "final check failed");
        require(s1[n] == s2[0], "middle equality check failed");
        solved3 = true;
    }
}