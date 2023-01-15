import concurrent.futures

from Crypto.Util.number import *
from sage.all import *
from sage.arith.functions import lcm
from sage.structure.coerce import py_scalar_to_element

# https://mistsuu.github.io/Cryptsu/writeups/isitdtu-final/Dat%20is%20sad/

"""
    /function/ CRT_():

    "" Purpose:
        Function that calculates CRT on chunks of <SEG_SIZE> numbers in the array
        rather than the whole array at once. 

        Works pretty nice with big array and (probably) big number.

        Built on the base of Sage's crt() function.

    "" Args:
        r:           List of remainders.
        m:           List of modulus.
        SEG_SIZE=8:  Number of values that CRT should work on once at a time.
        debug=False: Print out some debug data.

"""


def CRT_(r, m, SEG_SIZE=8, debug=False):
    if debug:
        print(f"[ i ] Calculate CRT with chunk size {SEG_SIZE}...")
        print(f"[ i ] Start loop with len = {len(r)}")

    while len(r) != 1:
        newR = []
        newM = []
        for i in range(0, len(r), SEG_SIZE):
            if len(r) - i == 1:
                newR.append(r[i])
                newM.append(m[i])
            else:
                crt_ = crt(r[i : i + SEG_SIZE], m[i : i + SEG_SIZE])
                prod = 1
                for _m in m[i : i + SEG_SIZE]:
                    prod *= _m
                newR.append(crt_)
                newM.append(prod)
        r = newR
        m = newM

        if debug:
            print(f"[ i ] Update loop with len = {len(r)}")

    if debug:
        print(f"[ i ] Finished :D")

    return r[0]


# Got CRT
DEBUG = True
cs, ns = [], []


# ls -al n_*

name = """n_00864af113a4.py n_29a21357e6b1.py n_86c42142bc9b.py n_c2cc5dd4d524.py
n_0260e74721db.py n_2ce2085c841c.py n_87ae615f891a.py n_c43f09b8660e.py
n_04bf5db58c28.py n_2d0d84f6.py     n_886f060c9b17.py n_c7746d2f58e6.py
n_05ac7fcd3b68.py n_2de42a31eb8f.py n_8880c6b4fb75.py n_c7c7c5dcd229.py
n_063eae5562cf.py n_2e6b27433d64.py n_8a596639be49.py n_c7e96667c9a6.py
n_076466d0bf8c.py n_34ec8b9716c1.py n_8a81e84ea86d.py n_c8b116022a4d.py
n_099b05db078e.py n_3b42d0862212.py n_8c401ccc2393.py n_cfb9691786c2.py
n_0c7d78a48d7b.py n_471ee7d8d3a4.py n_8eabf53af226.py n_d2356c22d5e1.py
n_0dededbf.py     n_483de2a74e2b.py n_8fa4b6530be8.py n_d2febfb1a903.py
n_1007792235e1.py n_4b4066008155.py n_93ccc34aa3f7.py n_d5d4f0118243.py
n_10752e514502.py n_4b8954b98f3f.py n_93e307a8.py     n_d65972cebd9c.py
n_14132b24e096.py n_4cdaffc6de7d.py n_96e56324c0e1.py n_d780b400379d.py
n_1453c912dd3e.py n_4dfdc11e.py     n_98e83a359b4e.py n_d9b644f06132.py
n_146ebe8b1a83.py n_5115097f3816.py n_9a027f77a678.py n_dbc6c94ca48e.py
n_153c6511.py     n_54807ffa545c.py n_9dd8ee93afe5.py n_dc92356eab79.py
n_1575bed889aa.py n_54fb0096f06e.py n_a1a5a7a36ef3.py n_e04b9a72b4eb.py
n_15c8221e3997.py n_56ebf0b8de34.py n_a207683c1560.py n_e3e3bf05.py
n_1726a9a6a8ef.py n_5c9c1c6170f5.py n_a23b32b9ccf1.py n_e4fdbc6d1f64.py
n_1937ccb932ca.py n_6020218e56f3.py n_a38f55e0.py     n_e778f7ef4b63.py
n_1ad14500c61d.py n_6304e7105330.py n_a86f798346e5.py n_e7a5080b6e79.py
n_1b21109e7d14.py n_6b5ea6ceede6.py n_a8e5d14bb3db.py n_eaf3c73595f5.py
n_1bff6bfbd637.py n_6c65844daebe.py n_a97336ce3db9.py n_eb1a0c793ba9.py
n_2059fc394a60.py n_6d971b7e5837.py n_aca9401033a9.py n_ed0f06c224ed.py
n_223446a5e44b.py n_71dda359455e.py n_b0ac0a10480e.py n_ed2df689.py
n_22e8cb2f3daa.py n_773b11d4.py     n_b1e1ba89a90b.py n_eec909f79d06.py
n_23385cf5e47f.py n_7a79d46486d7.py n_b3fd9be55c63.py n_f4b616c31848.py
n_23c3570283fb.py n_7b20eb55.py     n_ba1604ee903e.py n_f82d95daba00.py
n_252e57c8.py     n_7c7020e39e3a.py n_bde0bd79bb04.py n_f9477afd.py
n_25662a58d082.py n_7da722b29170.py n_bfbffe450f8f.py n_fdb93751.py
n_25f328cec0d5.py n_7e7b7967.py     n_c0e962daba7c.py n_ff6762d4b191.py
n_278848c70ff8.py n_7f889b2a01b0.py n_c24a40b3bed0.py
n_28e32ed1.py     n_82c7c5eb8f93.py n_c27f2708991a.py
"""
name = name.strip().replace(" ", "").replace("\n", "").split(".py")
name = [n.lstrip("n_") for n in name if len(n) > 0]

prefix = [""]
if DEBUG:
    for suffix in name:
        exec(f"from n_{suffix} import ns as ns_{suffix}")
        exec(f"from c_{suffix} import cs as cs_{suffix}")
        exec(f"ns += ns_{suffix}")
        exec(f"cs += cs_{suffix}")
    cs = cs[:65537]
    ns = ns[:65537]
else:
    FLAG = b"SAMPLE_FLAG"
    m = bytes_to_long(FLAG)
    e = 65537
    for i in range(e):
        print(i)
        p, q = getPrime(512), getPrime(512)
        n = p * q
        c = pow(m, e, n)
        ns.append(n)
        cs.append(c)


print(len(ns), len(set(ns)))
print(len(cs), len(set(cs)))
assert len(set(ns)) == len(set(cs))


# m_65537 = crt(cs, ns) # <- too slow !
m_65537 = CRT_(cs, ns, debug=True)
print(long_to_bytes(Integer(m_65537).nth_root(65537)))
# ASIS{N3s7Ed_DLP_089823341e928d6d87f0e442245d5a765833b575}
