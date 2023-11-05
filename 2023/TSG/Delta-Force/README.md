# Delta Force Writeup

### TSG CTF 2023 - crypto 341 - 6 solves

> Commence Operation Delta!! Hint: Last part of this problem, discrete_log() function in sagemath is useful. Run ?discrete_log in sage CLI and read the document.

> [delta_force.tar.gz](delta_force.tar.gz)

#### Given Curve is Singular

We are given a curve in the form of [Weierstrass form](https://crypto.stanford.edu/pbc/notes/elliptic/weier.html): $E: y^{2} + a_{1}xy + a_{3}y = x^{3} +a_{2}x^{2} + a_{4} x + a_{6}$ over integer modulo ring $N = p q$, where $p$ and $q$ are hidden.

By checking the discriminant is zero, we find that the given curve is singular.
```python
def is_singular():
    b2 = a1**2 + 4 * a2
    b4 = 2 * a4 + a1 * a3
    b6 = a3**2 + 4 * a6
    b8 = a1**2 * a6 + 4 * a2 * a6 - a1 * a3 * a4 + a2 * a3**2 - a4**2
    Di = -(b2**2) * b8 - 8 * b4**3 - 27 * b6**2 + 9 * b2 * b4 * b6
    return Di % N == 0

assert is_singular(), "Curve is not singular"
```

#### Goal: Solve DLP over Integer Modulo `N` over Singular Curve

We are given points $P = (Px, Py)$ and $Q = (Qx, Qy)$. $Q = d P$ where $d$ is secret. Our goal is to recover $d$ which contains the flag.

Denote $EC(k)$ be the curve defined over modulo ring $k$, and $ord(EC(k))$ be the order of $EC(k)$. If we factor $N$, we can solve each DLP over $EC(p)$ and $EC(q)$ and combine them using [chinese remainder theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem).

#### Factorization of `N = pq`

We do not know the values of $p$ and $q$ yet. However, we know that elliptic curve operation is [not well defined](https://crypto.stackexchange.com/questions/72613/elliptic-curve-discrete-log-in-a-composite-ring) in composite ring($N$ is composite). Also, if singular curve is the form of cusp($y^2 = x^3$) over prime $r$, its order is $r$. $ord(EC(N)) = ord(EC(p)) \times ord(EC(q))$.

Assuming that $EC(p)$ is a cusp($ord(EC(p)) = p$), $N$ will be the multiple of $p = ord(EC(p))$. If we calculate scalar multiplication $N * P$ over $EC(N)$, operation will be not well defined. Let $t$ be the intermediate value which breaks down the operation, because $t$'s inverse does not exist over composite $N$. This means $gcd(t, N)$ will give a nontrivial factor, which results in factorization, obtaining $p$.

```python
def factor():
    try:
        ec.scalar(N, P)
    except Exception as e:
        t, _ = list(
            map(
                int,
                str(e).lstrip("inverse of Mod(").rstrip(") does not exist").split(", "),
            )
        )
    p = gcd(t, N)
    q = N // p
    return p, q
```

#### Solving DLP over `EC(p)`

Lets classify whether $EC(p)$ is a cusp(form $y^{2} = x^{3}$) or node(form $y^{2} = x^{3} + \alpha x^{2}$). To do this, we need to find a [singular point](https://en.wikipedia.org/wiki/Singular_point_of_a_curve). Compute partial derivatives of $EC(p)$ and find values where they vanish and also on a curve.

```python
def calc_singular_point(f):
    FF = f.base_ring()
    p = FF.order()

    dfdx = lambda x, y: FF(a1 * y - 3 * x**2 - 2 * a2 * x - a4)
    dfdy = lambda x, y: FF(2 * y + a1 * x + a3)

    A = FF(6)
    B = FF(4 * a2 + a1**2)
    C = FF(2 * a4 + a1 * a3)
    roots = solve_quadratic(A, B, C)

    for xp in roots:
        yp = FF((-a1 * xp - a3) * pow(2, -1, p))
        assert dfdx(xp, yp) == 0 and dfdy(xp, yp) == 0
        if f.subs(x=xp, y=yp) == 0:
            return xp, yp
```

After that, we shift the curve to set the singular point as origin $(0, 0)$.

```python
    f = f.subs(x=x + xp, y=y + yp)
    assert f.subs(x=0, y=0) == 0
    xy_coeff = f.coefficient(x * y)
    f = f.subs(y=y + xy_coeff * twoinv * x)
    assert f == x ** 3 - y ** 2, "Given curve is not a cusp"
```

We confirmed $EC(p)$ is a cusp. We can solve DLP easily when a singular curve is a cusp form. $EC(p)$ has group isomorphism with $GF(p)$, and can be regarded as an additive group (Theorem 2.30 [^book]).

$$\varphi : EC(p) \rightarrow GF(p), \quad (x, y) \rightarrow \frac{x}{y}, \quad \inf \rightarrow 0 $$

We use this isomorphism $\varphi$ to map points from $EC(p)$ to elements of the group ($GF(p), +$). We first also shift the points because curve has shifted and mapped to an additive group. Therefore $ord(EC(p)) = p$.

```python
    # shift points
    Pxp = Px - xp
    Pyp = Py - yp - xy_coeff * twoinv * Pxp
    assert f.subs(x=Pxp, y=Pyp) == 0

    Qxp = Qx - xp
    Qyp = Qy - yp - xy_coeff * twoinv * Qxp
    assert f.subs(x=Qxp, y=Qyp) == 0
    
    # map to additive group over FF
    Q_ = FF(FF(Qxp) // FF(Qyp)) 
    P_ = FF(FF(Pxp) // FF(Pyp))
```

Solving DLP over additive group is easy.

```python
    dp = Q_ // P_
```

We recovered $d_{p}$, which is the result of DLP over $EC(p)$ between $P$ and $Q$. Every implementation for this step is done at method `solve_dlp_over_p()`.

#### Solving DLP over `EC(q)`

Lets classify whether $EC(q)$ is a cusp(form $y^{2} = x^{3}$) or node(form $y^{2} = x^{3} + \alpha x^{2}$). Again, we need to find a [singular point](https://en.wikipedia.org/wiki/Singular_point_of_a_curve). Compute partial derivatives of $EC(p)$ and find values where they vanish, and also on a curve. We shift the curve to set the singular point as origin $(0, 0)$.

```python
    xq, yq = calc_singular_point(f)

    # change of variables to make (0, 0) as singular point
    f = f.subs(x=x + xq, y=y + yq)
    assert f.subs(x=0, y=0) == 0
    xy_coeff = f.coefficient(x * y)
    f = f.subs(y=y + xy_coeff * twoinv * x)
    
    assert alpha != 0
    assert f == x**3 + alpha * x**2 - y**2
```

We confirmed $EC(q)$ is a node of the form $y^{2} = x^{2} (x + \alpha)$. We have an isomorphism(Theorem 2.31 [^book]):

$$\phi: (x, y) \rightarrow \frac{y + \alpha x}{y - \alpha x}$$

$\alpha$ is not a quadratic residue in this challenge, so $\phi$ gives an isomorphism:

$$EC(q) \simeq S := \{ u + \alpha v | u, v \in GF(q), u^{2} - \alpha v^{2} = 1 \}$$

where the righthand side is a group under multiplication. This is called nonsplit multiplicative reduction. $S$ is a set of points which [field norm](https://en.wikipedia.org/wiki/Field_norm) is $1$. Let $K/F$ be an extension field when $F = GF(q)$. Norm map $Norm_{K/F}$ is [surjective](https://math.stackexchange.com/questions/143711/show-the-norm-map-is-surjective); [(Proof)](https://math.stackexchange.com/questions/1717178/extension-of-finite-fields-under-norm-map). By the proof, $ord(S)$(cardinality of kernel) is equal to $q + 1$. Confirmation:

```python
    # order of Elliptic curve over GF(q) = q + 1
    oq = q + 1
    ec = EC(FF, (a1, a2, a3, a4, a6))
    assert ec.iszeropoint(P) and ec.iszeropoint(Q)
    assert ec.scalar(oq, P) == ec.O and ec.scalar(oq, Q) == ec.O
```

We know $ord(EC(q)) = q + 1$. Luckily, $q + 1$ is $B$-smooth, so we can apply [Pohlig Hellman](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm) algorithm for solving the DLP.

```python
    factors = [2, 2148001447, ...]
    assert reduce(mul, factors) == oq
    # order is B-smooth where B = 2 ** 33
    B = 2**33
    assert all(fac << B for fac in factors)
```

Pohlig Hellman algorithm only cares about input elements form a finite abelian group whose order is a smooth integer, which is our case. Sagemath has [`discrete_log`](https://doc.sagemath.org/html/en/reference/groups/sage/groups/generic.html#sage.groups.generic.discrete_log) method implemented, which takes elements and operations to make every step of the algorithm well defined. Identity, inverse, addition must be defined over custom groups. Define `class ECPoint` which is a wrapper of a tuple, define operations, and plug in to `discrete_log`.

```python
    # ECPoint class for discrete_log
    class ECPoint:
        def __init__(self, point):
            self.point = point

        def is_zero(self):
            return self.point == EC.O

        def __eq__(self, other):
            return self.point == other.point

        def __hash__(self):
            return hash(self.point)

    # factory method for discrete_log
    add = lambda x, y: ECPoint(ec.add(x.point, y.point))
    inv = lambda x: ECPoint(ec.negate(x.point))

    # wrapping points with ECPoint class
    identity = ECPoint(ec.O)
    P_, Q_ = ECPoint(P), ECPoint(Q)

    # discrete_log time
    dq = discrete_log(
        Q_, P_, ord=oq, operation="other", identity=identity, inverse=inv, op=add
    )
```

Recovering $d_{q}$ takes about 10 minutes in my laptop, which is the result of DLP over $EC(q)$ between $P$ and $Q$. Every implementation for this step is done at method `solve_dlp_over_q()`.

#### Solving DLP over `EC(N)`

We solved DLP over $EC(p)$ and $EC(q)$. Combine the results using the Chinese remainder theorem.

```python
def solve_dlp_over_N():
    p, q = factor()
    dp = solve_dlp_over_p(p)
    dq = solve_dlp_over_q(q)
    return crt([dp, dq], [p, q + 1])
```

We have recovered $d$, which is the result of DLP over $EC(N)$ between $P$ and $Q$. 

#### Flag

Recover `flag` based on `d`.

```python
from Crypto.Util.number import long_to_bytes as l2b

flag = l2b(int(d))
flag = flag[: flag.index(b"}") + 1]
```

We get flag.

```
TSGCTF{@l1_y0u_n3Ed_IS_ReaDiNG_5ilvErman_ThE_@r1thmetic_of_e11iPtiC_cURVe5}
```

Problem src: [problem.sage](problem.sage) depending on [elliptic_curve.py](elliptic_curve.py)

Problem output: [output.txt](output.txt)

Exploit driver code: [solve.sage](solve.sage)

#### References

[^book]: Elliptic Curves: Number Theory and Cryptography 2nd Edition
