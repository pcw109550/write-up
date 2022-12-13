from sage.all import parallel, GF

def possibly_parallel(num_cores):
    if num_cores == 1:
        def _wrap(fun):
            def _fun(args):
                for a in args:
                    yield ((a,), None), fun(a)
            return _fun
        return _wrap
    return parallel(num_cores)

def supersingular_gens(E):
    """
    Compute generators of E, assuming E is supersingular
    with smooth order (p+1)^2 with factors 2 and 3 only.
    This is faster than the PARI method.
    """
    # Find a random point of order (p+1) (probability 1/3)
    p = E.base_ring().characteristic()
    while True:
        P = E.random_point()
        if ((p+1)//2) * P != 0 and ((p+1)//3) * P != 0:
            break

    while True:
        Q = E.random_point()
        if ((p+1)//2) * Q != 0 and ((p+1)//3) * Q != 0:
            # but is it linearly independent? (probability 1/3)
            w = P.weil_pairing(Q, p+1)
            if w**((p+1)/2) != 1 and w**((p+1)//3) != 1:
                return P, Q

def fast_log3(x, base):
    """
    Fast discrete log when elements are known to have order
    dividing 3^k
    """
    one = x.parent().one()
    powers = [base]
    b = base
    log_order = None
    for i in range(10_000):
        b = b**3
        if b.is_one():
            log_order = i+1
            break
        powers.append(b)
    if not b.is_one():
        raise Exception("impossible")
    digits = []
    #assert x**(3**log_order) == 1
    #assert base**(3**(log_order-1)) != 1
    for i in range(log_order):
        for d in range(3):
            if (x * powers[i]**d)**(3**(log_order-i-1)) == 1:
                digits.append((-d) % 3)
                if d:
                    x /= powers[i]**(3-d)
                break
        if x == 1:
            break
    #assert x == 1
    dlog = sum(d*3**i for i, d in enumerate(digits))
    return dlog

def test_fast_log3():
    K = GF(70 * 3**69 + 1)
    g = K.multiplicative_generator()
    g = g**70
    for _ in range(1000):
        r = K.random_element()**70
        dl = fast_log3(r, g)
        assert r == g**dl

