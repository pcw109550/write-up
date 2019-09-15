# Alone in the dark Writeup

### CryptoCTF 2019 - crypto 166 - 18 solves

> We are alone in the dark with a [single line](https://cryp.toc.tf/tasks/alone_in_the_dark_94ff86de52959c8800ff062a04a29460a013f916.txz)!

Solved after the CTF was ended.

#### Analysis of the given single equation

My goal is to find the values of `u`, `v`, `x`, `y` which satisfies the equation below.

```python
assert ((u+1)**2 + u**2 - v**2)**2 + ((x+1)**3 - x**3 - y**2)**4 + (gmpy2.is_prime(v) + 1)**6 + (gmpy2.is_prime(y) - 1)**8 + (len(bin(u)[2:]) - 664)**10 + (len(bin(x)[2:]) - 600)**12 == 664 - 600
```

By inspecting the equations, I immediately notice that terms in LHS must be positive(since they all have positive even exponents). Adding those six positive terms must result in the value of `64`. By simply using some inequalities(`gmpy2.is_prime(v) + 1` must be equal to `2`, so `2 ** 6 == 64`), I can derive the constraints shown below.

```python
assert (u + 1) ** 2 + u ** 2 == v ** 2 # Constraint 1
assert (x + 1) ** 3 - x ** 3 == y ** 2 # Constraint 2
assert is_prime(y) and is_prime(v)
assert u.nbits() == 664 and x.nbits() == 600
```

#### Solving Pellian equation

The first and second constraints have the form of [Pellian equation](https://en.wikipedia.org/wiki/Pell%27s_equation). I will first derive the constraints to Pellian form.

Constraint 1:
```python
  (u + 1) ** 2 + u ** 2 = v ** 2
2 * u ** 2 + 2 ** u + 1 = v ** 2
4 * u ** 2 + 4 ** u + 2 = 2 * v ** 2
(2 * u + 1) ** 2 - 2 * v ** 2 = -1
U = 2 * u + 1, V = v
=> U ** 2 - 2 * V ** 2 = -1
```

Constraint 2:
```python
    (x + 1) ** 3 - x ** 3 == y ** 2
   3 * x ** 2 + 3 * x + 1 == y ** 2
36 * x ** 2 + 36 * x + 12 == 12 * y ** 2
(6 * x + 3) ** 2 - 12 * y ** 2 = -3
X = 6 * x + 3, Y = y
=> X ** 2 - 12 * Y ** 2 == -3
```

I generalized the method of solving Pellian equation which was introduced [here](http://www.irishmathsoc.org/bull54/M5403.pdf). To solve the equation,

1. Find the fundamental solution and the next solution(by using [continued fraction](https://en.wikipedia.org/wiki/Continued_fraction) method).
2. Solution of the equation can be derived using recurrence. An example is given [here](https://math.stackexchange.com/questions/531833/generating-all-solutions-for-a-negative-pell-equation). Let (`x = x_{n}`, `y = y_{n}`, `n` is nonnegative integer) be the solution of the equation(`x ** 2 - D * y ** 2 = k`). The following relation is satisfied.
```
x_{n + 1} = a * x_{n} + b * D * y_{n}
y_{n + 1} = b * x_{n} + a * y_{n}
```
3. By knowing fundamental and the second solution, solve the equation to get the value of `a` and `b`. For example, `(x_{0}, y_{0}) = (1, 1)`, `(x_{1}, y_{1}) = (7, 5)` for constraint 1. `D = 2` in this case, so deriving the value of `a` and `b` is easy(solve linear equation `7 = a + 2 *b b`, `5 = a + b`). I get `a = 3`, `b = 2` for the first contraint.
4. Use the recurrence equation to generating infinitely many solutions.

By generating solutions for the given equations, and using the leftover constraints, I could calculate the values of `u`, `v`, `x` and `y`. I get the flag:

```
CCTF{07f594e5fb8f6d5f82e5cce06e2a2c74c1bffce370cd904821fdd71027faa084}
```

exploit driver code: [solve.sage](solve.sage)

given code: [alone_in_the_dark.py](alone_in_the_dark.py)