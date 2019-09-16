#!/usr/bin/env python3

import random
from supercurve import SuperCurve, curve

def main():
    curve = SuperCurve(
        field = 14753, order = 7919,
        a = 1, b = -1, g = (1, 1),
    )
    # print curve parameters generically
    print(curve)

    # xP = Q
    secret_scalar = random.randrange(curve.order)
    base = curve.g
    pub = curve.mult(secret_scalar, base)
    print("Public key: {}".format(pub))
    print("Secret scalar: {}".format(secret_scalar))

    while True:
        user_input = input("What is the secret? ")

        if curve.mult(user_input, base) == pub:
            with open("flag.txt", "r") as f:
                print(f.read())
            break
        else:
            print("WRONGGG!")
            continue

    return 0

if __name__ == "__main__":
    exit(main())
