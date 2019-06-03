from pwn import *
from verifier import *
from itertools import chain
import csv

# context.log_level = "DEBUG"

data = []
with open("signatures.csv", "r") as infile:
    incsv = csv.reader(infile)
    for row in incsv:
        data.append(row)


def forge(msg, weird_addr):
    msg_list = msg.split(' ')
    log.info("Original msg: {:s}".format(msg))
    log.info("Source addr:  {:s}".format(msg_list[0]))
    log.info("Dest addr:    {:s}".format(msg_list[5]))
    log.info("Forge Dest addr to {:s}".format(weird_addr))
    assert len(weird_addr) == 64
    msg_list[5] = weird_addr
    assert msg_list[1] == 'sent'
    assert float(msg_list[2]) < 500
    assert msg_list[3] == 'zuccoins'
    assert msg_list[4] == 'to'
    assert len(msg_list[5]) == 64
    assert len(msg_list) == 6
    msg = " ".join(msg_list)
    log.info("Forged msg:   {:s}".format(msg))
    return msg


def main():
    # Will forge first transaction
    s = data[0]
    top_identity, h_msg, signature, others = parse_signed_message(s)
    msg = s[1]
    weird_addr = "0" * 64
    forged_msg = forge(msg, weird_addr)
    h_msg_forged = s256(forged_msg)

    bit_stream_forged = bit_stream_from_msg(h_msg_forged)
    sign_stream = group_by_n(signature, 2)

    initial = make_top_hash_from_leaves(msg_to_hashes(h_msg, signature))
    temp_hash = make_top_hash_from_others(initial, others[:3])

    assert others[3][0] == '1'
    assert others[4][0] == '1'
    assert len(others) == 5
    assert "11" == "{:b}".format(int(h_msg_forged[::-1], 16))[:2]
    assert others[3][0] == "{:b}".format(int(h_msg_forged[::-1], 16))[0]
    assert others[4][0] == "{:b}".format(int(h_msg_forged[::-1], 16))[1]

    top_hash = s256(others[3][1] + temp_hash)
    top_hash = s256(others[4][1] + top_hash)

    assert top_hash == top_identity

    # generate forged transaction
    forged_identity = top_identity
    forged_signature = [others[4][1], others[3][1] + temp_hash]
    forged_others = []

    forged = []
    forged += [forged_identity]
    forged += [forged_msg]
    forged += forged_signature
    forged += forged_others

    # sanity check
    a, b = verify_signed_message(forged)
    c = msg_internal_validity(forged[1], forged[0])

    assert (a == b) and c

    p = remote("challenges.fbctf.com", 8088)
    p.recvuntil("Enter signed transaction row: ")
    p.sendline(",".join(forged))
    p.recvline()
    p.recvline()
    flag = p.recvline().strip()
    log.success(flag)
    p.close()

    flag = "fb{reduce_reuse_recycle_is_bad_advice_for_ots}"

if __name__ == "__main__":
    main()
