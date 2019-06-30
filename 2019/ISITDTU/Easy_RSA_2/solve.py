from config import k1, k2, c, e, n
from Crypto.Util.number import GCD, inverse, long_to_bytes as l2b
import gmpy2


def fermat_factorization(n):
    factor_list = []
    gmpy2.get_context().precision = 2048
    a = int(gmpy2.sqrt(n))

    a2 = a * a
    b2 = gmpy2.sub(a2, n)

    while True:
        a += 1
        b2 = a * a - n

        if gmpy2.is_square(b2):
            b2 = gmpy2.mpz(b2)
            gmpy2.get_context().precision = 2048
            b = int(gmpy2.sqrt(b2))
            factor_list.append([a + b, a - b])

        if len(factor_list) == 2:
            break

    return factor_list


def main():
    factor_list = fermat_factorization(n)
    [X1, Y1] = factor_list[0]
    [X2, Y2] = factor_list[1]
    assert X1 * Y1 == n
    assert X2 * Y2 == n

    p1 = GCD(X1, X2)
    p2 = X1 / p1
    q1 = GCD(Y1, Y2)
    q2 = Y1 / q1

    phi = (p1 - 1) * (q1 - 1) * (p2 - 1) * (q2 - 1)
    d = inverse(e, phi)
    flag = l2b(pow(c, d, n))
    assert flag == "ISITDTU{C0ngratu1ati0ns_Attack_RSA_Multi_prim3!!!!}"

    print(flag)

if __name__ == "__main__":
    main()
