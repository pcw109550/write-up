from hashlib import sha256

# Constraints
# (u + 1) ** 2 + u ** 2 == v ** 2
# (x + 1) ** 3 - x ** 3 == y ** 2
# is_prime(y) and is_prime(v)
# u.nbits() == 664 and x.nbits() == 600

# Solve pell's equation


def solve_pell(N, c, numTry=1000000):
    # solve x ** 2 - N * y ** 2 == c
    cf = continued_fraction(sqrt(N))
    for i in range(numTry):
        denom = cf.denominator(i)
        numer = cf.numerator(i)
        if numer ** 2 - N * denom ** 2 == c:
            return numer, denom
    return None, None

# https://math.stackexchange.com/questions/531833/generating-all-solutions-for-a-negative-pell-equation
# http://nntdm.net/papers/nntdm-24/NNTDM-24-3-010-026.pdf
# http://www.irishmathsoc.org/bull54/M5403.pdf
# http://www.kurims.kyoto-u.ac.jp/EMIS/journals/GMN/yahoo_site_admin/assets/docs/1_GMN-8492-V28N2.190180001.pdf
# idea: find fundamental solution, next solutions are linearly related


# fundamental solution
X, Y = solve_pell(2, -1)
while True:
    assert X ** 2 - 2 * Y ** 2 == -1
    X, Y = 3 * X + 4 * Y, 2 * X + 3 * Y
    if X % 2 != 1:
        continue
    if not is_prime(Y):
        continue
    u, v = Integer((X - 1) / 2), Y
    if u.nbits() != 664:
        continue
    break
assert (u + 1) ** 2 + u ** 2 == v ** 2
assert is_prime(v)
assert u.nbits() == 664

# fundamental solution
X, Y = solve_pell(12, -3)
while True:
    assert X ** 2 - 12 * Y ** 2 == -3
    X, Y = 7 * X + 24 * Y, 2 * X + 7 * Y
    if X % 6 != 3:
        continue
    if not is_prime(Y):
        continue
    x, y = Integer((X - 3) / 6), Y
    if x.nbits() != 600:
        continue
    break
assert (x + 1) ** 3 - x ** 3 == y ** 2
assert is_prime(y)
assert x.nbits() == 600

flag = "CCTF{" + sha256(str(u) + str(v) + str(x) + str(y)).hexdigest() + "}"
assert flag == "CCTF{07f594e5fb8f6d5f82e5cce06e2a2c74c1bffce370cd904821fdd71027faa084}"

print(flag)
