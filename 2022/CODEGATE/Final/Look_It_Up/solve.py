import random
from typing import List

from solcx import compile_source, install_solc
from web3 import HTTPProvider, Web3
from web3.middleware import geth_poa_middleware

p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
challenge_address = "0x8EBd27597Ee2Cf89d3937bC5f47D1f8d6CCEbe00"
attacker_private_key = (
    "0xa6855daade7763293890ba6f8aceec84c40811653d22970650db5f7a962e52d3"
)
attacker_address = Web3.toChecksumAddress("0xe3d79d970545aad6656cf97c9b65ed657ff6acf4")

install_solc(version="0.8.0")

web3 = Web3(HTTPProvider("http://127.0.0.1:9545/"))
web3.middleware_onion.inject(geth_poa_middleware, layer=0)
chain_id = web3.eth.chain_id


def transact(bytecode):
    nonce = web3.eth.getTransactionCount(attacker_address)
    tx = {
        "from": attacker_address,
        "to": challenge_address,
        "gas": 1000000,
        "gasPrice": 7500000000,
        "nonce": nonce,
        "chainId": chain_id,
        "data": bytecode,
    }
    signed_tx = web3.eth.account.sign_transaction(tx, private_key=attacker_private_key)
    tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
    tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    return tx_receipt


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


def challenge1(challenge):
    n = 3
    f = [0, 0, 0]
    t = [1, 1, 1, 1]
    s1 = [1, 1, 1, 1]
    s2 = [0, 0, 0, 0]
    data = challenge.functions.challenge1(n, f, t, s1, s2)._encode_transaction_data()
    transact(data)


def challenge2(challenge):
    beta = 11620231016609250318030392254631587239086697257654476177102973869357015871234
    gamma = (
        15383012000554373363906518632314487502819838942629401178134488526166171390775
    )
    n = 3
    f = [(p - gamma) % p, 0, 0]
    t = [1, 2, 3, 4]
    s1 = [1, 2, 3, 4]
    s2 = [4, 0, (p - gamma * (1 + beta)) % p, 0]
    data = challenge.functions.challenge2(n, f, t, s1, s2)._encode_transaction_data()
    transact(data)


def challenge3(challenge):
    n = 3
    f, t, s1, s2 = brute()
    data = challenge.functions.challenge3(n, f, t, s1, s2)._encode_transaction_data()
    transact(data)


def declaredSolved(challenge):
    transact(challenge.functions.declareSolved()._encode_transaction_data())


def main():
    with open("Challenge.sol") as f:
        source = f.read()

    compiled_sol = compile_source(source, output_values=["abi", "bin"])

    challenge = web3.eth.contract(
        abi=compiled_sol["<stdin>:Challenge"]["abi"],
        bytecode=compiled_sol["<stdin>:Challenge"]["bin"],
        address=challenge_address,
    )
    challenge1(challenge)
    challenge2(challenge)
    challenge3(challenge)
    declaredSolved(challenge)


if __name__ == "__main":
    main()
