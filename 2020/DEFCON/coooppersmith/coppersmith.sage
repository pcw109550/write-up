def coron(pol, X, Y, k=2, debug=False):
    """
    Returns all small roots of pol.

    Applies Coron's reformulation of Coppersmith's algorithm for finding small
    integer roots of bivariate polynomials modulo an integer.

    Args:
        pol: The polynomial to find small integer roots of.
        X: Upper limit on x.
        Y: Upper limit on y.
        k: Determines size of lattice. Increase if the algorithm fails.
        debug: Turn on for debug print stuff.

    Returns:
        A list of successfully found roots [(x0,y0), ...].

    Raises:
        ValueError: If pol is not bivariate
    """

    if pol.nvariables() != 2:
        raise ValueError("pol is not bivariate")

    P.<x,y> = PolynomialRing(ZZ)
    pol = pol(x,y)

    # Handle case where pol(0,0) == 0
    xoffset = 0

    while pol(xoffset,0) == 0:
        xoffset += 1

    pol = pol(x+xoffset,y)

    # Handle case where gcd(pol(0,0),X*Y) != 1
    while gcd(pol(0,0), X) != 1:
        X = next_prime(X, proof=False)

    while gcd(pol(0,0), Y) != 1:
        Y = next_prime(Y, proof=False)

    pol = P(pol/gcd(pol.coefficients())) # seems to be helpful
    p00 = pol(0,0)
    delta = max(pol.degree(x),pol.degree(y)) # maximum degree of any variable

    W = max(abs(i) for i in pol(x*X,y*Y).coefficients())
    u = W + ((1-W) % abs(p00))
    N = u*(X*Y)^k # modulus for polynomials

    # Construct polynomials
    p00inv = inverse_mod(p00,N)
    polq = P(sum((i*p00inv % N)*j for i,j in zip(pol.coefficients(),
                                                 pol.monomials())))
    polynomials = []
    for i in range(delta+k+1):
        for j in range(delta+k+1):
            if 0 <= i <= k and 0 <= j <= k:
                polynomials.append(polq * x^i * y^j * X^(k-i) * Y^(k-j))
            else:
                polynomials.append(x^i * y^j * N)

    # Make list of monomials for matrix indices
    monomials = []
    for i in polynomials:
        for j in i.monomials():
            if j not in monomials:
                monomials.append(j)
    monomials.sort()

    # Construct lattice spanned by polynomials with xX and yY
    L = matrix(ZZ,len(monomials))
    for i in range(len(monomials)):
        for j in range(len(monomials)):
            L[i,j] = polynomials[i](X*x,Y*y).monomial_coefficient(monomials[j])

    # makes lattice upper triangular
    # probably not needed, but it makes debug output pretty
    L = matrix(ZZ,sorted(L,reverse=True))

    if debug:
        print("Bitlengths of matrix elements (before reduction):")
        print(L.apply_map(lambda x: x.nbits()).str())

    L = L.LLL()

    if debug:
        print("Bitlengths of matrix elements (after reduction):")
        print(L.apply_map(lambda x: x.nbits()).str())

    roots = []

    for i in range(L.nrows()):
        if debug:
            print("Trying row %d" % i)

        # i'th row converted to polynomial dividing out X and Y
        pol2 = P(sum(map(mul, zip(L[i],monomials)))(x/X,y/Y))

        r = pol.resultant(pol2, y)

        if r.is_constant(): # not independent
            continue

        for x0, _ in r.univariate_polynomial().roots():
            if x0-xoffset in [i[0] for i in roots]:
                continue
            if debug:
                print("Potential x0:",x0)
            for y0, _ in pol(x0,y).univariate_polynomial().roots():
                if debug:
                    print("Potential y0:",y0)
                if (x0-xoffset,y0) not in roots and pol(x0,y0) == 0:
                    roots.append((x0-xoffset,y0))
    return roots

def main():
    p0 = 13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433644711173333
    n = 16560379602206469878642040724734782524471652184425568199376531218304959723079099494061696962898146302790990640308166046320996547003199970357682771281249444627288194940908457745348616259707293222668519330090699453824892126571382412313626098908456043505552225398755139173074200557063668562681181037016907178765434766138977799967705623358615398130863910258580093283414781103145514263119654540542844577475636596835335294772173922782276008155166627081245441786606779731368870953008009168947172908703060792853824608604243742851935101696271394947461262657372822142026376864657914137999684052968427854408796623411405505211057
    c = 3451020825210677666932098433930836269662122475416403384084714394767824196749293282942638559113373658327549931631285276052316827743778981013000400352487360552893150486900403845020205995077784231681130792989845165650838758462573845281702158168428257832033129558354488209501385341224275499626394586573876141360377428297314392613613481081302137752453403069344996820183524461573081734420028866648625754664903433417926847423531026210959406066292696183471652767244057263084413105129956020211676233313396536675992964608219579378424561537750394608656302969499112451293851934681220505198236332545869973738981702236640874292120
    nbits = n.nbits()
    X = Y = 2 ** 512 # Estimated size of x0, y0
    P.<x, y> = PolynomialRing(ZZ)
    pol = (2 * p0 * x + 1) * (2 * p0 * y + 1) - n
    x0, y0 = coron(pol, X, Y, k=2, debug=False)[0]
    assert n == (2 * p0 * x0 + 1) * (2 * p0 * y0 + 1)
    p = 2 * p0 * x0 + 1
    q = 2 * p0 * y0 + 1
    assert p * q == n
    e = 65537
    d = inverse_mod(e, (p - 1) * (q - 1))
    flag = pow(c, d, n)
    from Crypto.Util.number import long_to_bytes as l2b
    flag = l2b(flag)
    print(flag)

if __name__ == '__main__':
    main()
