#!/usr/bin/env sage
import pwn
from ast import literal_eval

beta = 10
n = 100
q = 250007
k = 30

Px = PolynomialRing(GF(q), "x")
x = Px.gen()

Py = PolynomialRing(GF(q), "y")
y = Py.gen()


IP, PORT = "3.34.244.51", 9005
pwn.context.log_level = "DEBUG"

# https://eprint.iacr.org/2022/998.pdf
while True:

    try:
        tn = pwn.remote(IP, PORT)
        F = Py(literal_eval(tn.recvline(keepends=False).decode()))
        print(f"{F = }")

        GFy = GF(q**n, "y", modulus=F)
        BOUND = 0.51 * beta * n**2

        for trial in range(100):
            pwn.log.info(f"Trial #{trial}")
            samples = []
            for _ in range(k):
                sample = GFy(literal_eval(tn.recvline(keepends=False).decode()))
                samples.append(sample)

            queries = []
            for sample in samples:
                trace = int(sample.trace() % q)
                query = abs(trace) <= BOUND
                queries.append(query)
                result = sum(queries) >= 11
            pwn.log.info(f"{result = }")
            sendval = str(0 if result else 1).encode()
            tn.sendline(sendval)

        tn.interactive()
    except:
        tn.close()
    else:
        break

# codegate2022{h0w_m4NY_CrYp705y573m5_C4n_w3_8R34K_0V3r_7H3_5Umm3r?!?!}
