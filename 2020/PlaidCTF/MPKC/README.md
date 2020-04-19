# MPKC Writeup

### PlaidCTF 2020 - crypto 350 - 42 solves

#### Exploit

By searching based on the comments(`Jiahui Chen et al. cryptosystem, 80-bit security`), I found the [paper](https://eprint.iacr.org/2020/053.pdf) which introduces efficient algorithm to crack multivariate quadratic polynomial based encyption scheme. My goal is simply follow the exploit plan(step 1 to 3) at section 3 of the paper.

#### Supporting result of 3.1 and STEP 1

Solve systems of m quadratic equation which is public keys. Find linear combination to get rid of quadratic terms.

```python
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
```

#### STEP 2

By using basis obtained from STEP 1, get `n - a` linear polynomials `rs`.

```python
rs = []
pk_vector = vector(pk)
for basis in kernel_basis:
    rs.append(pk_vector.dot_product(basis))
assert len(rs) == n - a
```

#### STEP 3

Express `x{i}` where `i in range(q)` by `A{i}` where `i in range(a)`. Express `pk` by substituting `x{i}` by `A{i}`. `a = 10`, so bruteforcing values of `A{i}` became feasible. Brute each block of ciphertext, find `A{i}`. By knowing `A{i}`, I immediately know `x{i}` which is plaintext.

```python
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
```

I get flag:

```
PCTF{D1d_y0u_kn0w_Sage_h4S_MuLTiVar1at3_P0lynoMiaL_SeQu3NCe5?_:o}
```

Original problem: [gen.sage](gen.sage), [output](output)

Exploit code: [solve.sage](solve.sage) requiring [output.sage](output.sage)
