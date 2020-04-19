#!/usr/bin/env sage
from itertools import combinations, product


def combine_blocks(blocks):
    x = 0
    for i in reversed(blocks):
        for j in reversed(i):
            x = x * q + Integer(j)
    ss = ""
    while x > 0:
        ss = chr(x % 256) + ss
        x = x // 256
    return ss

q, n, a, s = (3, 59, 10, 25)
m = n + 1 - a + s
FF = GF(q)
R = PolynomialRing(FF, ["x{}".format(i) for i in range(n)])
xs = R.gens()
[x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x18, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, x29, x30, x31, x32, x33, x34, x35, x36, x37, x38, x39, x40, x41, x42, x43, x44, x45, x46, x47, x48, x49, x50, x51, x52, x53, x54, x55, x56, x57, x58] = list(xs)

load('output.sage')

# pt = [[1, 0, 0, 2, 0, 1, 1, 2, 1, 1, 0, 2, 0, 1, 0, 2, 0, 2, 2, 0, 0, 0, 2, 0, 1, 1, 2, 1, 0, 2, 1, 2, 1, 2, 2, 1, 1, 1, 0, 0, 1, 2, 1, 0, 0, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0], [1, 0, 0, 2, 1, 1, 2, 1, 2, 2, 1, 2, 2, 2, 2, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 2, 0, 2, 0, 1, 1, 1, 2, 1, 1, 2, 2, 1, 2, 1, 2, 0, 1, 0, 0, 2, 1, 1, 1, 1, 0, 2, 2, 2, 0], [1, 2, 0, 2, 2, 2, 2, 0, 0, 1, 1, 1, 2, 1, 2, 2, 0, 0, 1, 0, 0, 2, 0, 0, 2, 2, 1, 2, 1, 2, 0, 1, 2, 1, 2, 1, 0, 0, 2, 0, 0, 2, 0, 2, 1, 0, 1, 1, 1, 0, 0, 2, 1, 2, 0, 2, 2, 1, 0], [1, 1, 1, 2, 0, 1, 2, 0, 1, 1, 1, 2, 2, 2, 1, 1, 0, 1, 1, 1, 0, 1, 0, 2, 1, 0, 0, 2, 0, 1, 0, 0, 0, 2, 0, 0, 0, 2, 0, 1, 2, 2, 0, 0, 1, 0, 1, 2, 1, 0, 1, 2, 2, 1, 0, 2, 0, 1, 0], [2, 0, 0, 1, 2, 0, 0, 1, 2, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 2, 1, 1, 1, 0, 2, 0, 1, 2, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 2, 1, 0, 2, 1, 0, 2, 2, 0, 2, 2, 0, 2, 2, 0, 0, 1, 1, 1], [1, 2, 2, 1, 0, 1, 1, 2, 1, 0, 1, 1, 0, 2, 2, 1, 2, 2, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]]
# print(combine_blocks(pt))
# exit()

print('STEP 1: Solve systems of m quadratic equation')
Quad = []
for i in range(m):
    coeffs = []
    coeffs += [pk[i].coefficient(xs[j] ** 2) for j in range(n)]
    coeffs += [pk[i].coefficient(xs[j] * xs[k]) for j, k in combinations(range(n), 2)]
    Quad.append(coeffs)
Quad = matrix(FF, Quad)
# Evidence of 3.1: Linearly independent set of n - a degree-one polynomial
kernel_basis = Quad.kernel().basis()
assert len(kernel_basis) == n - a

print('STEP 2: Obtain n - a independent degree-one polynomials')
rs = []
pk_vector = vector(pk)
for basis in kernel_basis:
    rs.append(pk_vector.dot_product(basis))
assert len(rs) == n - a

print('STEP 3: Bruteforce a variables in GF(q)')
# actual value of As
pt_A = []
# actual value of xs
pt = []

for blocknum, enc_block in enumerate(enc):
    print('Brute block {} out of {}'.format(blocknum + 1, len(enc)))
    d = vector(enc_block)

    # particular solution
    A = Matrix(FF, [[rs[i].coefficient(xs[j]) for j in range(n)] for i in range(n-a)])
    b = vector([d.dot_product(kernel_basis[i]) - rs[i].constant_coefficient() for i in range(n-a)])
    x_p = A.solve_right(b)
    A_kernel = A.right_kernel().basis_matrix()

    RA = PolynomialRing(FF, ["A{}".format(i) for i in range(a)])
    As = RA.gens()
    [A0, A1, A2, A3, A4, A5, A6, A7, A8, A9] = As
    x_sub = []

    # Express xs by As
    for i, col in enumerate(A_kernel.columns()):
        # Add homogenous sol with particular sol
        x_sub.append(vector(col).dot_product(vector(As)) + FF(x_p[i]))

    # Sanity check
    for i, basis in enumerate(kernel_basis):
        eq = d.dot_product(basis) - rs[i].constant_coefficient()
        coeffs = [FF(rs[i].coefficient(xs[j])) * x_sub[j] for j in range(n)]
        assert sum(coeffs) == eq

    # Is there a better way? :C
    # Express pk by As by substitution
    pk_sub = []
    for i in range(m):
        sub = []
        # Quadratic term
        sub += [FF(pk[i].coefficient(xs[j] ** 2)) * (x_sub[j] ** 2) for j in range(n)]
        sub += [FF(pk[i].coefficient(xs[j] * xs[k])) * (x_sub[j] * x_sub[k]) for j, k in combinations(range(n), 2)]
        # linear term
        sub += [FF(pk[i].monomial_coefficient(xs[j])) * x_sub[j] for j in range(n)]
        # constant
        sub += [FF(pk[i].constant_coefficient())]
        pk_sub.append(sum(sub))

    found = False
    for A_cand in product(range(q), repeat=a):
        if found:
            break
        for i in range(m):
            cand = FF(pk_sub[i](*A_cand))
            if cand == d[i]:
                if i == m - 1:
                    print('As = ', A_cand)
                    found = True
                    pt_A.append(A_cand)
            else:
                break

    # Plug in values of As to xs which is plaintext
    pt_block = []
    for x_sub_elem in x_sub:
        sub = []
        sub += [FF(x_sub_elem.coefficient(As[i])) * pt_A[-1][i] for i in range(a)]
        sub += [FF(x_sub_elem.constant_coefficient())]
        pt_block.append(sum(sub))
    print('xs = ', pt_block)
    pt.append(pt_block)

flag = combine_blocks(pt)
assert flag == 'PCTF{D1d_y0u_kn0w_Sage_h4S_MuLTiVar1at3_P0lynoMiaL_SeQu3NCe5?_:o}'
print(flag)

# https://eprint.iacr.org/2020/053.pdf
