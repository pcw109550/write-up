# 해킹방어대회(CTF) 후기 - CODEGATE 2022 본선 Blockchain Challenge `Look It Up` 문제 풀이

> Aimed to be submitted to KAIST Orakle Blockchain Academy

안녕하세요. 2022년 11월 7일~8일 개최된 CODEGATE 2022 국제해킹방어대회(CTF)에서 KAIST GoN 팀으로 대학생부 [우승](https://cs.kaist.ac.kr/board/view?bbs_id=news&bbs_sn=10476&page=1&skey=subject&svalue=&menu=83)을 하였습니다. 우리 팀은 저 포함 4인 팀으로 구성되었으며, 저는 본선 중 블록체인 및 암호학 관련 문제들을 풀어 우승에 기여하였습니다. 

이 글에서는 CTF에 대한 소개 및, 본선에 출제된 블록체인 문제(문제명: `Look It Up`)에 대한 풀이 및 이를 이해하기 위한 배경지식을 다루고자 합니다. 이 글이 블록체인 보안을 이해하는 데 있어 즐거운 출발점이 되었으면 좋겠습니다.

## CTF란?

CTF는 Capture The Flag의 약자입니다. 정보보안 대회 중 하나로, 암호학(Crypto), 웹 보안(Web Security), 시스템 해킹(Pwnable), 역공학(Reversing) 등 다양한 분야에서 출제된 문제(Challenge)를 푸는 대회입니다. 최근 들어 블록체인 기술이 진화하고, 블록체인 보안의 중요성이 대두됨에 따라 블록체인 보안 관련 문제가 CTF에 등장하고 있습니다. 유명 크립토 투자 회사인 [Paradigm](https://www.paradigm.xyz/)도 매년 블록체인 보안 관련 [Paradigm CTF](https://ctf.paradigm.xyz/)를 개최합니다. 

CTF는 정보보안 전문가부터 뉴비까지 참여하여, 우리들의 실력을 측정하고 향상하는 매우 좋은 기회입니다. 운이 좋으면 저처럼 상금도 얻을 수 있죠. 이 과정에서, 다른 사람들과 협력할 수도 있기에 협동심을 키울 수도 있습니다. 제가 생각하였을 때, CTF의 가장 큰 장점은, 모르는 지식이 등장하였을 때, 두려워하지 않고 빠른 시간 안에 이를 이해하여 응용할 수 있는 능력이 키워진다는 것입니다. 또한, 사소한 디테일까지 빠트리지 않고 문제에 접근하는 능력도 길러집니다. ~~그리고 매우 재밌습니다.~~

CTF는 보통 대학교나 회사, 국가 기관이 개최하며, 개인이 대회를 여는 경우도 있습니다. 뉴비를 위한 CTF부터, 정보보안 고인물을 위한 CTF까지, 난이도가 매우 다양합니다. 제가 참여한 [CODEGATE CTF](http://codegate.org/sub/introduce)는 과학기술정보통신부가 주최한, 2008년부터 개최된 유명한 대회입니다. 

그렇다면 CTF 문제를 푼다라는 것은 어떤 의미이며, 채점은 어떻게 이루어지는지 알아봅시다. 문제들은, 출제자가 의도적으로 취약점을 넣어서 작성한 프로그램 혹은 데이터로 이루어집니다. 문제 풀이자는, 취약점을 발견하여 허락되지 않은 데이터를 읽거나, 프로그램을 의도하지 않은 상태로 조종합니다. 그 증거로 `flag`를 찾습니다. 여기서 통상적으로 `flag`란, alphanumeric하면서 너무 길지 않은 문자열입니다. 가령, `flag{yay_here_is_your_secret}`가 예시가 되겠습니다. 문제 풀이자는 `flag`를 출제자의 server에 제출하여, 점수를 얻게 됩니다. 보통은 쉬운 문제 일수록 많이 풀리게 되고, 점수가 떨어지는 Dynamic scoring 방식입니다. 대회 시간동안 얻어낸 점수의 총합이 가장 큰 팀이 우승하게 됩니다. 아래는 실제 대회 Scoreboard입니다.

<p align="center">
    <img src="./codegate22f_scoreboard.jpg" alt="scoreboard" width="200" />
</p>

## CTF 문제 맛보기

아주 간단한 블록체인 문제를 예시로 살펴봅시다. 아래의 이더리움 스마트 컨트랙트 코드 및 그 주소가 문제 풀이자에게 주어집니다.

```solidity
contract Challenge {
    string private flag;

    constructor(string memory _flag) {
        flag = _flag;
    }

    function query() public payable returns (string memory) {
        require(msg.value >= 10000 ether);
        return flag;
    }
}
```

문제의 의도는 명백합니다. 우리는 `flag`의 값을 알아내야 합니다. 언뜻 보기엔 10000 ETH를 지불하여 payable인 `query` 메소드를 호출하여 `flag`를 얻어내야 할 것만 같습니다. 하지만 우리는 저렇게 큰 돈이 없습니다. 어떻게 해야 할까요?

[스마트 컨트랙트 위의 모든 데이터는 읽을 수 있습니다!](https://medium.com/hackernoon/your-private-solidity-variable-is-not-private-save-it-before-it-becomes-public-52a723f29f5e) 변수가 `private`로 선언되었더라도 말이죠. `getStorageAt` Ethereum JSONRPC(`getStorageAt(contract address, 0, latest)`)를 사용하여 slot 0번째 저장공간을 읽으면 `flag`를 얻을 수 있습니다!(`flag` 의 길이가 32 bytes 미만이라고 가정하였습니다. [FYI](https://ethereum.stackexchange.com/questions/107282/storage-and-memory-layout-of-strings)) 문제 풀이자는 얻어낸 `flag`를 출제자의 server에 제출하여, 점수를 얻습니다. 또한 문제 풀이자는 private keyword를 사용하였더라도, 블록체인 위의 모든 데이터는 읽을 수 있다는 중요한 사실을 상기하였습니다.

## CODEGATE 2022 본선 Blockchain Challenge `Look It Up` 같이 풀어보기

더 많은 것을 배우고, `flag`를 얻기 위해 이제는 CODEGATE 2022 본선 블록체인 문제인 `Look It Up` 문제를 단계별로 같이 풀어봅시다. 대회 문제는 위 맛보기보다 훨씬 어렵습니다! 차근차근 문제를 부셔보도록 합시다. 단순 해답을 제시하는 것이 아니라, 대회 도중 문제를 풀이하는데 있어 제가 진행하였던 생각에 대하여 자세히 설명해보겠습니다.

### 문제 만져보기

문제의 Description입니다.

```
Oh wow, a solidity code. I have zero knowledge on solidity code. Better look it up.

This is deployed using Paradigm CTF 2022's dockerfiles. For example, see

https://github.com/paradigmxyz/paradigm-ctf-2022/tree/main/sourcecode
https://github.com/paradigmxyz/paradigm-ctf-infrastructure
In other words, this is deployed using foundry's default settings. Please test your solutions before deploying the challenge.

Also, make sure to kill your instances after you get the flag.

nc 3.34.81.192 31337
```

Description을 읽어보니, Paradigm CTF에서 사용하였던 [인프라](https://github.com/paradigmxyz/paradigm-ctf-infrastructure)를 사용하였다고 하네요. 주어진 문제 endpoint를 접속해봅시다. [`nc`](https://en.wikipedia.org/wiki/Netcat) command를 활용하여, 주어진 IP, PORT를 사용하여 문제와 상호작용합니다(현재는 문제 서버가 종료되어 endpoint에 접속할 수 없습니다. 인프라를 사용하여 같은 환경을 구축할 수 있습니다).

```sh
$ nc 3.34.81.192 31337
1 - launch new instance
2 - kill instance
3 - get flag
action? 1
ticket please: kaistgonbestteam
```

문제를 만져보기 위하여, Stdin으로 action(`1`) 및 ticket(`kaistgonbestteam`)을 입력하였습니다. 그에 대한 Stdout으로 다음의 결과를 얻습니다.

```
your private blockchain has been deployed
it will automatically terminate in 30 minutes
here's some useful information
uuid:           13d5525e-d46f-4b30-861c-ab2b16be2eff
rpc endpoint:   http://3.34.81.192:8545/13d5525e-d46f-4b30-861c-ab2b16be2eff
private key:    0xa6855daade7763293890ba6f8aceec84c40811653d22970650db5f7a962e52d3
setup contract: 0x5aB95D9cabC56DA53767904dD1884A918fa17902
```

저를 위한 개인 블록체인이 배포되었다고 합니다. 문제 Setup 스마트 컨트랙트 주소 및 ETH가 (문제를 풀 만큼) 들어 있는 주소의 private key, 블록체인과 상호작용할 수 있는 RPC endpoint가 주어집니다. 

이와 함께 문제 배포파일인 [Challenge.sol](Challenge.sol), [Setup.sol](Setup.sol)이 주어집니다.

`Setup.sol`은 다음과 같습니다.
```solidity
pragma solidity 0.8.0;

import "./Challenge.sol";

contract Setup {
    
    Challenge public challenge;

    constructor() {
        challenge = new Challenge();
    }
    
    function isSolved() public view returns (bool) {
        return challenge.solved();
    }
}
```

Challenge 컨트랙트를 배포하고, 문제가 풀렸는지 확인하기 위한 `isSolved` 메소드가 구현된 것을 확인할 수 있습니다. `isSolved` 메소드가 참을 반환하게 만들면 문제가 풀립니다. 이는 [인프라의 소스 코드](https://github.com/paradigmxyz/paradigm-ctf-infrastructure/blob/08a0f1a0fc3bd1f661ec425021bc46f5bdf9b906/images/eth-challenge-base/eth_sandbox/launcher.py#L181)에서 확인해볼 수 있습니다. 결과적으로 다음의 Python 코드가 동작하여 문제 풀이 여부를 판별합니다.

```python
def is_solved_checker(web3: Web3, addr: str) -> bool:
    result = web3.eth.call(
        {
            "to": addr,
            "data": web3.sha3(text="isSolved()")[:4],
        }
    )
    return int(result.hex(), 16) == 1
```

`isSolved` 메소드가 참을 반환하기 위해, `challenge.solved()`의 구현을 보러 `Challenge.sol`로 넘어갑시다. `Challenge.sol`는 다음과 같습니다.

```solidity
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
```

114줄의 Solidity 코드입니다. 문제의 목표는 `solved` bool 변수를 참으로 만드는 것입니다. 그래야 Setup 컨트랙트의 `isSolved` 메소드가 참을 반환하기 때문이죠. 그렇다면 `solved` bool 변수를 taint하는 곳이 어디가 있는지 살펴봅시다. 아래의 `declareSolved` 메소드가 유일합니다.

```solidity
function declareSolved() public {
    if(solved1 == true && solved2 == true && solved3 == true) {
        solved = true;
    }
}
```

`solved1`, `solved2`, `solved3` bool 변수들을 모두 참으로 만들어야만 합니다. 이를 위해서는, `require`에 걸리지 않는 입력을 사용하여 `challenge1`, `challenge2`, `challenge3`을 호출하여야만 합니다. 정리하여 이 문제는 부분 문제가 3개가 있으며, 각 문제는 다른 문제에 영향을 주지 않는 형태입니다. Math-heavy해 보이는 이 세 `challenge`를 풀어봅시다. 코드로 표현된 형태를 수식으로 옮겨 생각합니다.

문제를 본격적으로 접근하기에 앞서, 기본적으로 확인해야 할 사항이 있습니다. 바로 코드에서 사용되는 Solidity 컴파일러의 버전입니다. `pragma solidity 0.8.0;`이므로, 언어 자체에 integer overflow detection이 [내장](https://solidity-by-example.org/hacks/overflow/)되어 있습니다. 또, 각 `challenge`간 유사성을 확인할 수 있습니다. `sanity_check` 메소드, `final_check` 메소드를 모두 통과하여야 합니다. 이 공통 메소드들을 우선 분석해봅시다.

문제에 제시된 $p$는 254 bit 크기의 [소수](http://factordb.com/index.php?query=21888242871839275222246405745257275088548364400416034343698204186575808495617)입니다. $p$의 수학적 특성을 확인하기 위하여 $p - 1, p + 1$를 소인수분해 하여 [smoothness](https://en.wikipedia.org/wiki/Smooth_number)를 확인하였으나 좋은 성질은 얻지 못하였습니다.

### `sanity_check` 분석

메소드 인자는 다음의 조건을 만족하여야 합니다.

1. $n + 1$이 2의 거듭제곱입니다.
2. $f$의 길이는 $n$입니다. $t$, $s_{1}$, $s_{2}$의 길이는 $n + 1$입니다.
3. $f$, $t$, $s_{1}$, $s_{2}$를 이루는 원소는 [유한체](https://en.wikipedia.org/wiki/Finite_field) $GF(p)$ 의 원소 입니다(모두 $p$ 미만의 정수이어야 합니다). $p$가 소수이기 때문입니다. 

### `final_check` 분석

`sanity_check` 메소드와 비교하였을 때, $\beta$, $\gamma$ 변수가 추가됩니다. 각 `challenge`의 로직에서 이 두 변수를 계산하여, `final_check` 메소드에게 확인을 맡기는 방식입니다. 메소드를 통과하기 위하여 다음의 등식 $A$ 을 만족하여야 합니다. 모든 계산은 $GF(p)$위에서 이루어집니다. 

$$ (1 + \beta)^{n} \prod_{i=0}^{n} (\gamma (1 + \beta) + t[i + 1] \beta + t[i]) \prod_{i=0}^{n} (\gamma + f[i]) = \newline 
\prod_{i=0}^{n} (\gamma (1 + \beta) +  s_{1}[i + 1] \beta + s_{1}[i]) \prod_{i=0}^{n} (\gamma (1 + \beta) + s_{2}[i + 1] \beta + s_{2}[i]) \quad \cdots \quad A
$$

이 때, $t$의 원소들과 $f$의 원소들의 교집합이 공집합이어야 합니다. 쉽게 말해, $t$에 포함된 원소들은 $f$에 포함되지 않아야 합니다. 그 반대도 마찬가지입니다. 

### `challenge1` 통과하기

$\beta$와 $\gamma$는 다음과 같이 계산됩니다.

```solidity
bytes32 beta = keccak256(abi.encode(n, f, t, s1, s2, uint256(1)));
bytes32 gamma = keccak256(abi.encode(n, f, t, s1, s2, uint256(2)));
```

[`keccak256`](https://en.wikipedia.org/wiki/SHA-3) 메소드는 [암호학적 해시 함수(CHF)](https://en.wikipedia.org/wiki/Cryptographic_hash_function)이므로, [avalanche effect](https://en.wikipedia.org/wiki/Avalanche_effect)를 만족합니다. 쉽게 말하여, 입력이 살짝 바뀌어도, 출력이 많이(50% 확률로 출력의 각 비트가 뒤집어집니다) 바뀐다는 것입니다. 또, `abi.encode` 메소드는 [dynamic type를 포함](https://docs.soliditylang.org/en/v0.8.0/abi-spec.html)하여, 여러 데이터를 인코딩합니다. 인코딩으로 인하여 abi collision을 피합니다. `abi.encode`는 일대일 대응(bijectivity)인 [affine 함수](https://mathworld.wolfram.com/AffineFunction.html)입니다. 쉽게 말하여, 주어진 입력을 $x$라고 하였을 때, 출력이 $ax + b$ 형태인 변환을 말하는 것입니다. 

위와 같은 수학적 고찰을 수행하여, $n, f, t, s_{1}, s_{2}$에 어떤 값을 사용하든, $\beta$와 $\gamma$의 값을 같게 만들 수는 없다는 결론을 얻습니다. `abi.encode`의 마지막 인자가 각각 `uint256(1)`, `uint256(2)`로 의도적으로 다르게 설정되어 있기 때문입니다. $\beta \neq \gamma$임을 확정하고 적합한 $n, f, t, s_{1}, s_{2}$값을 찾아봅시다. 

다음 세 항이 비슷한 구조를 가짐을 관찰합니다.

$$ \prod_{i=0}^{n} (\gamma (1 + \beta) + t[i + 1] \beta + t[i]), \prod_{i=0}^{n} (\gamma (1 + \beta) +  s_{1}[i + 1] \beta + s_{1}[i]),  \prod_{i=0}^{n} (\gamma (1 + \beta) + s_{2}[i + 1] \beta + s_{2}[i]) $$

만족해야 하는 등식 $A$를 간단하게 하기 위하여 $t$와 $s_{1}$의 값을 동등하게 설정합니다. 

$$ (1 + \beta)^{n} \prod_{i=0}^{n} (\gamma + f[i]) = \prod_{i=0}^{n} (\gamma (1 + \beta) + s_{2}[i + 1] \beta + s_{2}[i])
$$

관찰을 통하여 $f$와 $s_{2}$의 모든 원소를 $0$으로 설정하여, 변환된 등식이 성립함을 확인합니다.

$$ (1 + \beta)^{n} \prod_{i=0}^{n} \gamma = \prod_{i=0}^{n} (\gamma (1 + \beta)) $$

정리하여 $\beta, \gamma, n$의 값에 상관없이, $t = s_{1}$만 만족하면 `challenge1`를 해결할 수 있습니다. 
$n$과 $t, s_{1}$의 원소들의 실제 값은 앞서 정리한 조건을 만족하도록 임의로 설정하였습니다. $f$와 $t$의 원소가 겹치지 않는 것을 확인하였습니다.

$$ n = 1, f = [0], t = [1, 1], s_{1} = [1, 1], s_{2} = [0, 0] $$

지금까지는 간단한 수학 문제로 보입니다. 다음 `challenge`로 넘어가 봅시다.

### `challenge2` 통과하기

`challenge1`과 비교하여 $\beta$와 $\gamma$를 계산하는 로직이 Solidity inline assembly로 바뀌었습니다. `challenge1`과 비슷하게 `keccak256` opcode로 $\beta$와 $\gamma$를 계산합니다. 그럼 `challenge1`의 결과를 그대로 사용하면 되지 않을까? 어림도 없습니다. 다음의 `require`가 추가됩니다.

```solidity
require(s1[n] == s2[0], "middle equality check failed");
```

굉장히 골치가 아픕니다. 긴 시간 펜을 굴려봐도 $s_{1}[n] = s_{2}[0]$까지 만족하는 입력을 찾기가 쉽지 않습니다. 수학적으로 더 고민해봅시다. $\beta$와 $\gamma$는 우리가 입력한 메소드 인자에 따라서 바뀌니, $\beta$와 $\gamma$의 값에 상관없이 $s_{1}[n] = s_{2}[0]$일 때 $n, f, t, s_{1}, s_{2}$값을 찾아야 합니다. 조건을 만족하는 $n, f, t, s_{1}, s_{2}$의 존재성에 대하여 의문점을 가지기 시작합니다.

#### 유한체 위에서의 다항식 인수분해의 유일성

$A$의 우변을 이루는 $2n$개의 다항식 중 $s_{1}[n], s_{2}[0]$에 영향받는 다항식을 골라냅니다. $P(\beta, \gamma) = (\gamma(1 + \beta) + s_{1}[n] \beta + s_{1}[n - 1]), Q(\beta, \gamma) = (\gamma(1 + \beta) + s_{2}[1] \beta + s_{2}[0])$라 할 때, $P$와 $Q$가 영향권입니다. 두 식 모두 $\beta, \gamma$에 관하여 1차식입니다. 위 두 항에 대한 효과를 상쇄하기 위하여 등식 $A$의 좌변을 관찰해봅시다. 

$$ (1 + \beta)^{n} \prod_{i=0}^{n} (\gamma (1 + \beta) + t[i + 1] \beta + t[i]) \prod_{i=0}^{n} (\gamma + f[i]) $$

$(1 + \beta)^{n}$을 배분하여 정리하면 다음과 같습니다. 배분하는 이유는, $\beta$와 $\gamma$에 대한 차수를 맞춰주기 위해서입니다.

$$ \prod_{i=0}^{n} (\gamma (1 + \beta) + t[i + 1] \beta + t[i]) \prod_{i=0}^{n} (\gamma (1 + \beta) + f[i] \beta + f[i]) $$

$A$의 좌변을 이루는 $2 n$개의 다항식 중 우변의 $P$와 $Q$가 다항식 2개와 대응됩니다. $P$와 $Q$를 제외한, 우변을 이루는 $2n - 2$개의 다항식의 계수를 관찰해보면, $0 < i < n$에 인 $i$에 대하여 $s_{1}[i]$와 $s_{2}[i]$는 다항식에 각각 2번 사용되게 됩니다.

이러한 성질에 의하여 $P(\beta, \gamma) \mid \Pi_{i=0}^{n} (\gamma (1 + \beta) + t[i + 1] \beta + t[i])$이어야 하고, $Q(\beta, \gamma) \mid \Pi_{i=0}^{n} (\gamma (1 + \beta) + f[i] \beta + f[i]) $이어야 합니다. $P$, $Q$의 위치가 바뀌어도 됩니다. 한 쪽에 쏠리게 배치할 수 없다는 뜻입니다. 그렇다면, $s_{1}[n] = s_{2}[0]$를 만족하여야 하기 떄문에 `final_check`에서 유래된 $t$의 원소들과 $f$의 원소들의 교집합이 공집합인 조건을 만족할 수 없습니다. 이 모든 논증은 [유한체 위에서의 다항식 인수분해](https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields) 결과가 유일하다는 사실에 바탕을 둡니다. 

#### EVM Assembly 분석

그렇다면 앞서 한 가정이 틀렸다는 결론입니다. 자연스럽게 $\beta$와 $\gamma$를 계산하는 로직이 왜 바뀌었을까에 대한 고민을 시작합니다. 정말로 $\beta$와 $\gamma$는 우리가 입력한 메소드 인자에 따라서 결정될지 다시 확인하기 위해 inline assembly를 차근차근 뜯어봅시다. [EVM Opcode Specification](https://ethervm.io/)를 봅시다.

```solidity
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
```

1. `mload(0x40)`: `ptr = memory[0x40:0x40 + 32]`를 수행합니다. `0x40`에는, EVM의 [free memory pointer](https://ethereum.stackexchange.com/questions/9603/understanding-mload-assembly-function)가 저장되어 있습니다. 연산하기 위하여 필요한 메모리의 위치를 우선 확보하는 것입니다.
2. `calldatacopy(ptr, 4, len)`: `memory[ptr:ptr + len] = msg.data[4:4 + len])`을 수행합니다. 즉, transaction calldata의 `4`번째(0 indexed) 바이트부터 `4 + len` 바이트까지 memory에 복사합니다. 
3. `mstore(add(ptr, len), 1)`: `memory[ptr + len: ptr + len + 32] = 1`을 수행합니다. 앞서 복사한 메모리에 바로 `1`을 이어 붙입니다.
4. `beta := keccak256(ptr, add(len, 32))`: `beta = keccak256(memory[ptr:ptr + len + 32])`을 수행합니다. 메모리에 명시적으로 적은 데이터를 해싱하여 그 결과를 `beta`에 저장합니다. 32를 더하는 이유는, 앞서 `1`이 적혔을 때 32바이트를 사용하였기 때문입니다.
5. `mstore(add(ptr, len), 2)`: `memory[ptr + len:ptr + len + 32] = 2`를 수행합니다. `1`을 적었던 곳에 다시 `2`를 적습니다.
6. `gamma := keccak256(ptr, add(len, 32))`: `gamma = keccak256(memory[ptr:ptr + len + 32])`을 수행합니다. 메모리에 명시적으로 적은 데이터를 해싱하여 그 결과를 `gamma`에 저장합니다. 32를 더하는 이유는 4번과 동일합니다.

이 때, `len = (12 + 4 * n) * 0x20`입니다. [`calldatacopy`](https://ethervm.io/#37) instruction을 사용하였으므로, transaction calldata의 구조를 확인합시다. calldata의 일부(`msg.data[4:4 + len]`)를 그대로 복사해서 $\beta$와 $\gamma$를 구하였습니다.

#### Transaction Calldata Layout

calldata의 구조를 다루는 자세한 [글](https://degatchi.com/articles/reading-raw-evm-calldata)입니다. 이 내용을 참조하여 calldata를 뜯어봅시다. `function challenge2(uint256 n, uint256[] memory f, uint256[] memory t, uint256[] memory s1, uint256[] memory s2)` 메소드를 아래의 인자로 호출한 transaction의 calldata를 만듭니다. `challenge2`를 통과할 수는 없지만, calldata 구조 파악 용도입니다.

$$ n = 3, f = [1, 2, 3], t = [4, 5, 6, 7], s_{1} = [8, 9, 10, 11], s_{2} = [12, 13, 14, 15] $$

[web3py](https://web3py.readthedocs.io/en/v5/)와 [py-solc-x](https://solcx.readthedocs.io/en/latest/)를 이용하여 calldata를 생성합니다. 아래는 `0x` prefix와 function selector를 제외하고 32 바이트 단위로 자르는 Python 코드입니다.

```python
from solcx import compile_source, install_solc
from web3 import HTTPProvider, Web3

web3 = Web3()

install_solc(version="0.8.0")

with open("Challenge.sol") as f:
    source = f.read()

compiled_sol = compile_source(source, output_values=["abi", "bin"])

challenge = web3.eth.contract(
    abi=compiled_sol["<stdin>:Challenge"]["abi"],
    bytecode=compiled_sol["<stdin>:Challenge"]["bin"],
)

n = 0x3
f = [0x1, 0x2, 0x3]
t = [0x4, 0x5, 0x6, 0x7]
s1 = [0x8, 0x9, 0xa, 0xb]
s2 = [0xc, 0xd, 0xe, 0xf]

calldata = challenge.functions.challenge2(n, f, t, s1, s2)._encode_transaction_data()
# remove 0x prefix and remove function selector b6ebb13b
layout = bytes.fromhex(calldata.lstrip("0x"))[4:]
for i in range(len(layout) // 32):
    print("{:03x}".format(i * 32), layout[32 * i : 32 * i + 32].hex())
```

결과는 다음과 같습니다. 입력된 인자가 `0x1`부터 `0xf`까지 쌓여있습니다. 곳곳에 직접 입력하지 않은 다른 값들도 있습니다. 결국 EVM은 아래의 calldata를 파싱하여, function selector를 활용하여 메소드를 호출합니다. [ABI specification](https://docs.soliditylang.org/en/v0.8.0/abi-spec.html#abi)에 의하여, 각 32(0x20) 바이트가 어떤 의미를 가지는지 주석을 달아봅시다. $n$을 제외한 $f, t, s_{1}, s_{2}$는 [dynamic type](https://docs.soliditylang.org/en/v0.8.0/abi-spec.html#use-of-dynamic-types)입니다. EVM Stack Machine이 메소드 호출 시 인자가 어떻게 전달되는지 이해할 수 있습니다. Dynamic type에 대하여, EVM이 calldata로부터 데이터를 파싱하기 위하여, argument의 길이 및 calldata내부에서의 offset를 calldata가 포함된다는 것을 예시를 통하여 알 수 있습니다. 32 바이트씩 총 24줄이 출력되었습니다.

```
000 0000000000000000000000000000000000000000000000000000000000000003    # 1st argument: n = 0x3
020 00000000000000000000000000000000000000000000000000000000000000a0    # 2nd argument offset: f starts at 0x0a0
040 0000000000000000000000000000000000000000000000000000000000000120    # 3rd argument offset: t starts at 0x120
060 00000000000000000000000000000000000000000000000000000000000001c0    # 4th argument offset: s1 starts at 0x1c0
080 0000000000000000000000000000000000000000000000000000000000000260    # 5th argument offset: s2 starts at 0x260
0a0 0000000000000000000000000000000000000000000000000000000000000003    # 2nd argument: f.length = 0x3
0c0 0000000000000000000000000000000000000000000000000000000000000001    # 2nd argument: f[0] = 0x1
0e0 0000000000000000000000000000000000000000000000000000000000000002    # 2nd argument: f[1] = 0x2
100 0000000000000000000000000000000000000000000000000000000000000003    # 2nd argument: f[2] = 0x3
120 0000000000000000000000000000000000000000000000000000000000000004    # 3rd argument: t.length = 0x4
140 0000000000000000000000000000000000000000000000000000000000000004    # 3rd argument: t[0] = 0x4
160 0000000000000000000000000000000000000000000000000000000000000005    # 3rd argument: t[1] = 0x5
180 0000000000000000000000000000000000000000000000000000000000000006    # 3rd argument: t[2] = 0x6
1a0 0000000000000000000000000000000000000000000000000000000000000007    # 3rd argument: t[3] = 0x7
1c0 0000000000000000000000000000000000000000000000000000000000000004    # 4th argument: s1.length = 0x4
1e0 0000000000000000000000000000000000000000000000000000000000000008    # 4th argument: s1[0] = 0x8
200 0000000000000000000000000000000000000000000000000000000000000009    # 4th argument: s1[1] = 0x9
220 000000000000000000000000000000000000000000000000000000000000000a    # 4th argument: s1[2] = 0xa
240 000000000000000000000000000000000000000000000000000000000000000b    # 4th argument: s1[3] = 0xb
260 0000000000000000000000000000000000000000000000000000000000000004    # 5th argument: s2.length = 0x4
280 000000000000000000000000000000000000000000000000000000000000000c    # 5th argument: s2[0] = 0xc
2a0 000000000000000000000000000000000000000000000000000000000000000d    # 5th argument: s2[1] = 0xd
2c0 000000000000000000000000000000000000000000000000000000000000000e    # 5th argument: s2[2] = 0xe
2e0 000000000000000000000000000000000000000000000000000000000000000f    # 5th argument: s2[3] = 0xf
```

앞서 $\beta$와 $\gamma$ 계산 시 calldata의 일부(`msg.data[4:4 + len]`), `len = (12 + 4 * n) * 0x20` 가 사용되었습니다. 위의 예시에서는 $n = 3$이므로, `len = (12 * 4 * 3) * 0x20 = 24 * 0x20`, 즉, 위에 출력된 모든 calldata가 `msg.data[4:4 + len]`에 해당한다는 것을 알 수 있습니다.

#### Calldata offset 조작을 통한 $\beta$와 $\gamma$ 고정하기

만약 $\beta$와 $\gamma$가 입력된 인자에 상관없이 고정된 값이고, 우리가 알고 있는 값이라면 등식 $A$및 $s_{1}[n] = s_{2}[0]$를 만족하는 입력을 쉽게 찾을 수 있을까요? `challenge1`에서 수행하였던 것처럼 등식 $A$를 다시 관찰합시다.

$$ (1 + \beta)^{n} \prod_{i=0}^{n} (\gamma (1 + \beta) + t[i + 1] \beta + t[i]) \prod_{i=0}^{n} (\gamma + f[i]) = \newline 
\prod_{i=0}^{n} (\gamma (1 + \beta) +  s_{1}[i + 1] \beta + s_{1}[i]) \prod_{i=0}^{n} (\gamma (1 + \beta) + s_{2}[i + 1] \beta + s_{2}[i]) \quad \cdots \quad A
$$

 $\beta$와 $\gamma$값을 알고 있고, 이 값이 상수라면 위 식을 만족하는 입력 $n, f, t, s_{1}, s_{2}$를 찾는건 매우 쉬워집니다. 간단하게 생각하여, 등식 $A$의 좌변과 우변을 모두 $0$으로 만들어봅시다.

$$ f[0] = -\gamma, s_{2}[n - 1] = 0, s_{2}[n] = - \gamma(1 + \beta)$$

위 값을 사용하면, 나머지 입력과 관계없이 좌변과 우변 모두 $0$이 됨을 알 수 있습니다. 여기서 주의할 점은 인자의 모든 원소가 $GF(p)$의 원소에 포함되어야 하므로, 실제 값을 사용할 때는 $p$로 나눈 나머지를 사용해야 합니다. 그렇다면 어떻게 $\beta$와 $\gamma$가 입력된 인자에 상관 없는, 값을 아는 상수로 설정할 수 있을까요? 

놀랍게도 앞서 설명한 calldata layout의 구조를 응용하면 가능합니다. `msg.data[4: 4 + len]`가 $\beta$와 $\gamma$에 사용됩니다. 만약, 메소드 인자 $n, f, t, s_{1}, s_{2}$를 정상적으로 전달하면서, `msg.data[4: 4 + len]`의 값을 상수로 만들어버릴 수 있다면 $\beta$와 $\gamma$를 값을 아는 상수로 설정할 수 있습니다. `msg.data[4: 4 + len]`가, $\beta$와 $\gamma$에 영향을 받지 않는 독립 상수로 바뀌어버렸기 때문입니다. Calldata layout에 적어놓은 주석을 다시 살펴봅시다.

두 번째 인자인 $f$에 해당하는 calldata 시작 위치 및 $f$에 포함된 값을 나타내는 부분은 다음과 같습니다.

```
...
020 00000000000000000000000000000000000000000000000000000000000000a0    # 2nd argument offset: f starts at 0x0a0
...
0a0 0000000000000000000000000000000000000000000000000000000000000003    # 2nd argument: f.length = 0x3
0c0 0000000000000000000000000000000000000000000000000000000000000001    # 2nd argument: f[0] = 0x1
0e0 0000000000000000000000000000000000000000000000000000000000000002    # 2nd argument: f[1] = 0x2
100 0000000000000000000000000000000000000000000000000000000000000003    # 2nd argument: f[2] = 0x3
...
```

Calldata에 담긴 값은 공격자가 조정할 수 있습니다. 다시 말하여 인자의 offset도 조정할 수 있습니다. 이를 활용하여, `0x300`바이트에 $f$의 실제 인자를 적도록 offset을 수정합니다. 기존 $f$에 포함된 값을 담는 주소는 임의의 값으로 채워줍니다. 저는 `0`로 채워보겠습니다.

```
...
020 0000000000000000000000000000000000000000000000000000000000000300    # 2nd argument modified offset: f starts at 0x300
...
0a0 0000000000000000000000000000000000000000000000000000000000000000    # dummy value: 0x0
0c0 0000000000000000000000000000000000000000000000000000000000000000    # dummy value: 0x0
0e0 0000000000000000000000000000000000000000000000000000000000000000    # dummy value: 0x0
100 0000000000000000000000000000000000000000000000000000000000000000    # dummy value: 0x0
...
300 0000000000000000000000000000000000000000000000000000000000000003    # 2nd argument: f.length = 0x3
320 0000000000000000000000000000000000000000000000000000000000000001    # 2nd argument: f[0] = 0x1
340 0000000000000000000000000000000000000000000000000000000000000002    # 2nd argument: f[1] = 0x2
360 0000000000000000000000000000000000000000000000000000000000000003    # 2nd argument: f[2] = 0x3
```

이처럼 calldata를 조작하면 $\beta$와 $\gamma$에 영향을 주는 `msg.data[4:4 + len]`부분을 상수로 고정할 수 있습니다. 그러므로 $\beta$와 $\gamma$의 값도 고정됩니다! 앞서 도출한 결과를 적용하여 `challenge2`를 해결할 수 있습니다. $n, f, t, s_{1}, s_{2}$의 실제 값은 아래와 같이 설정합니다. 앞서 도출한 $f[0], s_{2}[n - 1], s_{2}[n - 2]$를 사용하고, $s_{1}[n] = s_{2}[0]$ 조건까지 맞춰줍니다. 이 조건들을 제외한 인자 값은 임의로 설정하였습니다.

$$ n = 3, f = [-\gamma, 0, 0], t = s_{1} = [1, 2, 3, 4], s_{2} = [4, 0, - \gamma (1 + \beta), 0]$$

고정된 $\beta$와 $\gamma$값을 알아내기 위하여 다른 인자인 $t, s_{1}, s_{2}$에 해당하는 부분도 offset을 수정합니다. `msg.data[4:4 + len]`의 값을 다음과 같이 고정합니다.

```
000 0000000000000000000000000000000000000000000000000000000000000003    # 1st argument: n = 0x3
020 0000000000000000000000000000000000000000000000000000000000000300    # 2nd argument modified offset: f starts at 0x300
040 0000000000000000000000000000000000000000000000000000000000000380    # 3rd argument modified offset: t starts at 0x380
060 0000000000000000000000000000000000000000000000000000000000000420    # 4th argument modified offset: s1 starts at 0x420
080 00000000000000000000000000000000000000000000000000000000000004c0    # 5th argument modified offset: s2 starts at 0x4c0
0a0 0000000000000000000000000000000000000000000000000000000000000000    # dummy value: 0x0
0c0 0000000000000000000000000000000000000000000000000000000000000000    # dummy value: 0x0
0e0 0000000000000000000000000000000000000000000000000000000000000000    # dummy value: 0x0
100 0000000000000000000000000000000000000000000000000000000000000000    # dummy value: 0x0
120 0000000000000000000000000000000000000000000000000000000000000000    # dummy value: 0x0
140 0000000000000000000000000000000000000000000000000000000000000000    # dummy value: 0x0
160 0000000000000000000000000000000000000000000000000000000000000000    # dummy value: 0x0
180 0000000000000000000000000000000000000000000000000000000000000000    # dummy value: 0x0
1a0 0000000000000000000000000000000000000000000000000000000000000000    # dummy value: 0x0
1c0 0000000000000000000000000000000000000000000000000000000000000000    # dummy value: 0x0
1e0 0000000000000000000000000000000000000000000000000000000000000000    # dummy value: 0x0
200 0000000000000000000000000000000000000000000000000000000000000000    # dummy value: 0x0
220 0000000000000000000000000000000000000000000000000000000000000000    # dummy value: 0x0
240 0000000000000000000000000000000000000000000000000000000000000000    # dummy value: 0x0
260 0000000000000000000000000000000000000000000000000000000000000000    # dummy value: 0x0
280 0000000000000000000000000000000000000000000000000000000000000000    # dummy value: 0x0
2a0 0000000000000000000000000000000000000000000000000000000000000000    # dummy value: 0x0
2c0 0000000000000000000000000000000000000000000000000000000000000000    # dummy value: 0x0
2e0 0000000000000000000000000000000000000000000000000000000000000000    # dummy value: 0x0
```

위 값을 calldata의 일부로 설정하여, $\beta$와 $\gamma$를 계산합니다. 최종 calldata는 위 데이터 앞에 알맞은 [function selector](https://solidity-by-example.org/function-selector/)를 추가해야 합니다. `challenge2` 메소드의 function selector의 값은 `b6ebb13b`이었습니다. $\beta$와 $\gamma$를 구하기 위해 간단한 테스트 스마트 컨트랙트를 작성하였습니다. 

```solidity
pragma solidity 0.8.0;

contract Test {
    uint256 public p = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    event Calc(bytes32 beta, bytes32 gamma);

    function test2(uint256 n, uint256[] memory f, uint256[] memory t, uint256[] memory s1, uint256[] memory s2) public {
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
        emit Calc(beta, gamma);
    }
}
```

`test2` 메소드를 실행하는 transaction의 receipt에 $\beta$와 $\gamma$가 포함되어 있습니다. 도출된 값은 아래와 같습니다.

$$ \beta = \texttt{0x19b0d1539797a71ab7ce45e7209ec515ce4cca508bad4b7671b58b1d2509af02} $$

$$ \gamma = \texttt{0x220279eb49199b1cdffbc3b5e4f673d917a9d78aeeeedf464e161556d8b91337} $$

$\beta$와 $\gamma$를 구하였으므로 $n, f, t, s_{1}, s_{2}$가 결정되어 `challenge2`를 해결하였습니다. Calldata layout의 이해가 필요한 문제였습니다. 최종적으로 보내야 하는 calldata는 앞서 offset를 조작하고 dummy value로 채워진 `msg.data[4:4 + len]` 부분 뒤로 실제 인자 값을 다음과 같이 추가하여야 합니다.

```
300 0000000000000000000000000000000000000000000000000000000000000003    # 2nd argument: f.length = 0x3
320 0e61d4879818050cd85482009c8ae484108a10bd8aca914af5cbe03d1746ecca    # f[0] = -gamma % p
340 0000000000000000000000000000000000000000000000000000000000000000    # f[1] = 0x0
360 0000000000000000000000000000000000000000000000000000000000000000    # f[2] = 0x0
380 0000000000000000000000000000000000000000000000000000000000000004    # 3rd argument: t.length = 0x4
3a0 0000000000000000000000000000000000000000000000000000000000000001    # t[0] = 0x1
3c0 0000000000000000000000000000000000000000000000000000000000000002    # t[1] = 0x2
3e0 0000000000000000000000000000000000000000000000000000000000000003    # t[2] = 0x3
400 0000000000000000000000000000000000000000000000000000000000000004    # t[3] = 0x4
420 0000000000000000000000000000000000000000000000000000000000000004    # 4th argument: s1.length = 0x4
440 0000000000000000000000000000000000000000000000000000000000000001    # s1[0] = 0x1
460 0000000000000000000000000000000000000000000000000000000000000002    # s1[1] = 0x2
480 0000000000000000000000000000000000000000000000000000000000000003    # s1[2] = 0x3
4a0 0000000000000000000000000000000000000000000000000000000000000004    # s1[3] = 0x4
4c0 0000000000000000000000000000000000000000000000000000000000000004    # 5th argument: s2.length = 0x4
4e0 0000000000000000000000000000000000000000000000000000000000000004    # s2[0] = 0x4
500 0000000000000000000000000000000000000000000000000000000000000000    # s2[1] = 0x0
520 220ea990c9170f184ca10d4e43567db84935c5b2b82cd5fbfe69633867d82f12    # s2[2] = -gamma * (1 + beta) % p
540 0000000000000000000000000000000000000000000000000000000000000000    # s2[3] = 0x0
```

### `challenge3` 통과하기

마지막 단계인 `challenge3`입니다. $\beta$와 $\gamma$를 계산하는 로직이 아래와 같이 바뀌었습니다. $s_{1}[n] = s_{2}[0]$ 및 `sanity_check`, `final_check`를 통과하는 것은 동일합니다.

```solidity
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
```

`challenge2`와 동일하게 주어진 EVM Assembly를 분석해봅시다.

#### EVM Assembly 분석

1. `mload(0x40)`: `ptr = memory[0x40:0x40 + 32]`를 수행합니다. `0x40`에는, EVM의 [free memory pointer](https://ethereum.stackexchange.com/questions/9603/understanding-mload-assembly-function)가 저장되어 있습니다. 연산하기 위하여 필요한 메모리의 위치를 우선 확보하는 것입니다.
2. `mstore(ptr, beta)`: `memory[ptr:ptr + 32] = beta`를 수행합니다.
3. `mstore(add(ptr, 32), gamma)`: `memory[ptr + 32:ptr + 64] = gamma`를 수행합니다.
4. `mstore(add(ptr, 64), mload(add(0x80, mul(i, 32))))`: `memory[ptr + 64: ptr + 96] = memory[0x80 + 32 * i: 0x80 + 32 * (i + 1)]`를 수행합니다. `memory[0x80 + 32 * i: 0x80 + 32 * (i + 1)]`에는 calldata로부터 파싱된 실제 인자의 값이 저장되어 있습니다. calldata에 저장된 인자를 memory 영역에 적는 코드는 프로그래머가 직접 구현하는 것이 아닌, EVM assembly 형태로 미리 구현되어 있습니다. `challenge3(uint256 n, uint256[] memory f, uint256[] memory t, uint256[] memory s1, uint256[] memory s2)`에서 memory라는 키워드를 사용하였으므로, 메소드 로직 실행 전 메모리에 미리 calldata에 포함된 인자를 복사하고, 그 위치가 `memory[0x80 + 32 * i: 0x80 + 32 * (i + 1)]`인 것입니다.
5. `mstore8(add(ptr, 96), 1)`: `memory[ptr + 96] = 1`
6. `mstore8(add(ptr, 97), 2)`: `memory[ptr + 97] = 2`
7. `beta := keccak256(ptr, 97)`: `beta = keccak256(memory[ptr, ptr + 97])`, 즉 `[copied beta | copied gamma | i th parsed calldata | 1]`데이터를 해싱하여 `beta`를 업데이트합니다.
8. `gamma := keccak256(ptr, 98)`: `gamma = keccak256(memory[ptr, ptr + 98])`, 즉 `[copied beta | copied gamma | i th parsed calldata | 1 | 2 ]`데이터를 해싱하여 `gamma`를 업데이트합니다.
9. `i`값을 증가시켜가면서, 파싱된 calldata에 대하여 1번부터 8번까지의 로직을 반복합니다. 파싱된 calldata의 32 byte 개수는 `4 * n + 7`이므로, 주어진 모든 calldata에 대하여 반복문을 수행합니다. 각 iteration마다 $\beta$와 $\gamma$의 값이 업데이트 됩니다.

`challenge2`와는 다르게, EVM이 calldata내부에 포함된 offset및 인자를 직접 파싱합니다. 그리고 그 값을 그대로 $\beta$와 $\gamma$를 계산하는 데 활용합니다. calldata에 포함된 인자에 따라, $\beta$와 $\gamma$가 의존적입니다. `challenge2`에서 분석하였던 [유한체 위에서의 다항식 인수분해의 유일성](#유한체-위에서의-다항식-인수분해의-유일성)에 의해, 문제를 풀 수 없을 것만 같습니다.

지금까지는 문제에서 직접적으로 제시된, 컴파일 되지 않은 코드를 읽어서 분석하였습니다. 그렇다면 실제 EVM에 배포된 EVM bytecode를 의심할 차례입니다. 정말 내가 읽고 있는 코드의 symantic과 동일한 코드가 블록체인에서 동작하고 있는지 확인합니다.

#### Solidity Optimizer Keccak Caching Bug: $\beta = \gamma$ 확인하기

문제에서 제시된 코드와 블록체인에서 동작하는 코드가 달라지려면, EVM bytecode를 생성하는 Solidity 컴파일러의 버그가 존재하여야 합니다. 대회 당시 Solidity의 최신 버전은 [0.8.17](https://github.com/ethereum/solidity/releases/tag/v0.8.17)이지만, 문제에서 사용한 Solidity 버전은 `0.8.0`입니다. 자연스럽게, 두 버전 사이에 패치된 버그 리스트를 찾아봅니다. 

[Solidity blog](https://blog.soliditylang.org/)에 올라온 Security Alert 레이블이 붙은 글을 모두 읽던 중, [Solidity Optimizer Keccak Caching Bug](https://blog.soliditylang.org/2021/03/23/keccak-optimizer-bug/) 글을 발견하였습니다. `0.8.3` 이전의 모든 버전에 존재한 버그입니다. 버그의 요약은 다음과 같습니다.

> The bytecode optimizer incorrectly re-used previously evaluated Keccak-256 hashes. You are unlikely to be affected if you do not compute Keccak-256 hashes in inline assembly.

> Specifically, keccak256(mpos1, length1) and keccak256(mpos2, length2) in some cases were considered equal if length1 and length2, when rounded up to nearest multiple of 32 were the same, and when the memory contents at mpos1 and mpos2 can be deduced to be equal.

`challenge3`에서는 inline assembly로 해싱을 수행합니다. 문제 상황과 일치합니다. `beta := keccak256(ptr, 97)`, `gamma := keccak256(ptr, 98)`이기 때문입니다. 만약 버그가 발생하였다면, `beta = gamma := keccak256(ptr, 97)`에 대응되는 bytecode가 생성되었다는 것입니다. 내가 읽고 있는 코드의 symantic과 다른 코드가 블록체인에서 동작하고 있는지 `getCode` Ethereum JSONRPC(`getCode(contract address, latest)`)를 통하여 배포된 bytecode를 확인하여, 이를 [EVM decompilers](https://ethervm.io/decompile) 활용하여 로직으로 최적화하는 버그가 발생하였는지 확인합니다. 아래는 디컴파일된 $\beta$와 $\gamma$를 계산하는 로직입니다.

```solidity
...
var temp4 = memory[0x40:0x60];
memory[temp4:temp4 + 0x20] = var0;
memory[temp4 + 0x20:temp4 + 0x20 + 0x20] = var1;
memory[temp4 + 0x40:temp4 + 0x40 + 0x20] = memory[var2 * 0x20 + 0x80:var2 * 0x20 + 0x80 + 0x20];
memory[temp4 + 0x60:temp4 + 0x60 + 0x01] = 0x01;
memory[temp4 + 0x61:temp4 + 0x61 + 0x01] = 0x02;
var0 = keccak256(memory[temp4:temp4 + 0x61]);
var1 = var0;
...
```

`var0`은 $\beta$, `var1`은 $\gamma$에 해당됩니다. `var1 = var0;`라는 코드를 관찰하여, bytecode optimizer bug가 발생하여 $\beta = \gamma$임을 확인하였습니다. 로컬 환경에서도 확인할 수 있습니다. [`solc-select`](https://github.com/crytic/solc-select)으로 Solidity version을 `0.8.0`으로 맞춰 준 후, [`solc`](https://www.npmjs.com/package/solc)의 최적화 플래그 `--optimize`를 사용하여 버그 발생을 확인할 수도 있습니다.

```bash
$ solc-select install 0.8.0 && solc-select use 0.8.0
$ solc --optimize Challenge.sol --asm
$ solc Challenge.sol --asm
```

$\beta = \gamma$를 확인하였습니다. 이 강력한 조건을 활용하여 `challenge3`를 통과하는 $n, f, t, s_{1}, s_{2}$ 값을 구해봅시다. 동일한 symantic을 가진 python코드를 작성하여 전수조사를 실시하였습니다. 이때, $n = 3$으로 설정하였으며, 다른 인자의 값들은 $0, 1, 2$ 중 하나로 설정하였습니다. $\beta = \gamma$와 같은 강력한 조건이면 조사 범위를 이 정도로 한정해도 해가 존재할 것이라 생각하였습니다. $\beta = \gamma$의 값을 랜덤한 임의의 수로 설정하였습니다.

```python
import random
from typing import List

from web3 import Web3

p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
n = 3


def H(data: bytes) -> int:
    return Web3.toInt(Web3.soliditySha3(["bytes"], [data]))


def isPowerOf2(n: int) -> bool:
    while n % 2 == 0:
        n = n / 2
    return n == 1


def sanity_check(
    n: int, f: List[int], t: List[int], s1: List[int], s2: List[int]
) -> bool:
    assert isPowerOf2(n + 1)
    assert all([len(f) == n, len(t) == n + 1, len(s1) == n + 1, len(s2) == n + 1])
    assert all(all([0 <= x <= p for x in data]) for data in [f, t, s1, s2])


def final_check(
    n: int,
    f: List[int],
    t: List[int],
    s1: List[int],
    s2: List[int],
    beta: int,
    gamma: int,
) -> bool:
    LHS = 1
    for i in range(n):
        LHS = LHS * (1 + beta) % p
        mul = (gamma * (1 + beta) + beta * t[i + 1] + t[i]) % p
        LHS = LHS * mul * (gamma + f[i]) % p
    RHS = 1
    for i in range(n):
        mul1 = (gamma * (1 + beta) + beta * (s1[i + 1]) + s1[i]) % p
        mul2 = (gamma * (1 + beta) + beta * (s2[i + 1]) + s2[i]) % p
        RHS = RHS * mul1 * mul2 % p
    assert LHS == RHS, "LHS != RHS"
    for i in range(n):
        if all([f[i] != elem for elem in t]):
            return
    assert False, "f and t so equal"


def check3(n: int, f: List[int], t: List[int], s1: List[int], s2: List[int]):
    beta = gamma = random.randint(1, 1 << 128)
    sanity_check(n, f, t, s1, s2)
    final_check(n, f, t, s1, s2, beta, gamma)
    assert s1[n] == s2[0]


def brute() -> None:
    for i in range(3**15):
        val = i
        arr = []
        for _ in range(15):
            arr.append(val % 3)
            val //= 3
        f, t, s1, s2 = arr[:3], arr[3:7], arr[7:11], arr[11:15]
        try:
            check3(n, f, t, s1, s2)
        except:
            continue
        else:
            return f, t, s1, s2
    assert False


if __name__ == "__main__":
    f, t, s1, s2 = brute()
    print(f"{f = }")
    print(f"{t = }")
    print(f"{s1 = }")
    print(f"{s2 = }")
```

제 예상이 맞았습니다. 1초 이내로 $n, f, t, s_{1}, s_{2}$값을 찾을 수 있었습니다. 그 결과는 다음과 같습니다.

$$ n = 3, f = [2, 0, 0], t = [1, 0, 0, 0], s_{1} = [0, 1, 1, 0], s_{2} = [0, 0, 0, 0] $$

### 대망의 `flag` 얻기

`challenge1`, `challenge2`, `challenge3`를 모두 호출하여, `require`를 피하는 인자를 사용하여 `solved1`, `solved2`, `solved3` bool 변수를 모두 참으로 만들었습니다. `declaredSolved` 메소드를 마지막으로 호출하여, `solved` bool 변수를 참으로 만들어줍니다.

다시 문제 endpoint에 접속하여, `flag`를 얻어냅시다. 길고도 힘든 과정이었습니다.

```bash
$ nc 3.34.81.192 31337
1 - launch new instance
2 - kill instance
3 - get flag
action? 3
ticket please: kaistgonbestteam
codegate2022{1mpr0v1n6_pl00kup_15_h4rd_4f73r_4ll_bu7_47_l3457_w3_h4v3_2022/086_50_ju57_k33p_y0ur_h34r75_w4rm!_4l50_50l1d17y_0.8.3_15_h3r3_70_54v3_u5!}
```

저 긴 string이 `flag`입니다. 문제의 난이도에 걸맞게 플래그도 다량의 정보량을 함유하고 있습니다. 참고로 비슷하게 생긴 숫자와 알파벳을 섞어서 단어를 사용하는 것을 [Leetspeak](https://en.wikipedia.org/wiki/Leet)이라고 합니다. `flag`의 내용을 보아하니, 다음 사실을 배울 수 있었습니다.

1. 제시된 $GF(p)$위의 다항식은 zero knowledge [plonkup](https://eprint.iacr.org/2022/086.pdf)와 관련이 있습니다. IACR eprint 번호가 `2022/086` 입니다.
- `1mpr0v1n6_pl00kup_15_h4rd_4f73r_4ll_bu7_47_l3457_w3_h4v3_2022/086_`
2. `challenge2`에 해당하는 공격 기법을 [frozen heart vulnerability](https://blog.trailofbits.com/2022/04/18/the-frozen-heart-vulnerability-in-plonk/)라고 합니다. [CVE-2022-29566](https://nvd.nist.gov/vuln/detail/CVE-2022-29566)도 있습니다.
- `50_ju57_k33p_y0ur_h34r75_w4rm!_`
3. `challenge3`에서 사용된 solidity 버그는 `0.8.3` 버전에서 패치되었습니다.
- `4l50_50l1d17y_0.8.3_15_h3r3_70_54v3_u5!`

### Wrap Up

정리하여, zero knowledge plonkup의 소개 및 공격 기법, solidity 버그를 비빈 밀도 높은 문제였습니다. 이 글에서는 plonkup에 대한 이론적 분석은 하지 않았지만, zero knowledge에 대하여 흥미를 돋우는 좋은 문제였습니다. 적절하게 섞인 solidity gimmick도 재미있었습니다.

문제 저자인 [rkm0959](https://rkm0959.tistory.com/)이 쓰신 [문제 해설](https://zkresear.ch/t/codegate-ctf-2022-look-it-up-writeup-deeper-look-at-plookup/47)도 있습니다. 이 글과 다른 점은, 저는 문제 풀이자의 입장에서 zero knowledge에 대한 이해도 없이 문제를 풀이하였다는 것입니다. 또 출제자의 풀이는 onchain에서 문제를 풀이하는데 필요한 payload를 작성하였습니다. Zero knowledge에 대한 deep dive를 하려면, 출제자의 해설을 이해하거나, 제가 이어서 쓸 zero knowledge관련 글을 읽어주시면 감사하겠습니다. 다사다난하였던 긴 글을 끝까지 따라와 주셔서 감사합니다!

### Exploit Artifacts

최종 공격 코드는 [solve.py](solve.py)에 작성하였습니다. [requirements.txt](requirements.txt)가 의존성입니다. 각 `challenge1`, `challenge2`, `challenge3` 메소드가 문제의 각 단계를 풀이합니다. 실제 공격을 수행하려면, 앞서 언급하였듯이 인프라를 구축하여 로컬에 ethereum 클라이언트를 구동시킨 후, 문제를 배포하여야 합니다.
