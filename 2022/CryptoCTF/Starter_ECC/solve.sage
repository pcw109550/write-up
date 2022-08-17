from itertools import product

from Crypto.Util.number import long_to_bytes as l2b
from sage.rings.finite_rings.integer_mod import square_root_mod_prime

x = 10715086071862673209484250490600018105614048117055336074437503883703510511249361224931983788156958581275946729175531468251871452856923140435984577574698574803934567774824230985421074605062371141877954182153046477020617917601884853827611232355455223966039590143622792803800879186033924150173912925208583
a = 31337
b = 66826418568487077181425396984743905464189470072466833884636947306507380342362386488703702812673327367379386970252278963682939080502468506452884260534949120967338532068983307061363686987539408216644249718950365322078643067666802845720939111758309026343239779555536517718292754561631504560989926785152983649035
n = 117224988229627436482659673624324558461989737163733991529810987781450160688540001366778824245275287757373389887319739241684244545745583212512813949172078079042775825145312900017512660931667853567060810331541927568102860039898116182248597291899498790518105909390331098630690977858767670061026931938152924839936
p = 690712633549859897233
q = 651132262883189171676209466993073
r = 2
assert n == p**6 * q**5 * r**63


def sqrt(x, prime):
    return Integer(square_root_mod_prime(Mod(x, prime), prime))


def lift(f, p, k, previous):
    result = []
    df = diff(f)
    for lower_solution in previous:
        dfr = Integer(df(lower_solution))
        fr = Integer(f(lower_solution))
        if dfr % p != 0:
            t = (-(xgcd(dfr, p)[1]) * int(fr / p ** (k - 1))) % p
            result.append(lower_solution + t * p ** (k - 1))
        if dfr % p == 0:
            if fr % p**k == 0:
                for t in range(0, p):
                    result.append(lower_solution + t * p ** (k - 1))
    return result


def hensel_lifting(f, p, k, base_solution):
    solution = base_solution
    for i in range(2, k + 1):
        solution = lift(f, p, i, solution)
    return solution


E = EllipticCurve(Zmod(n), [a, b])


YSQ = x**3 + a * x + b

P.<tp> = PolynomialRing(Zmod(p ** 6), implementation='NTL')
fp = tp**2 - YSQ
pp = sqrt(YSQ % p, p)

basep = [pp, p - pp]
assert basep[0] ** 2 % p == YSQ % p
assert basep[1] ** 2 % p == YSQ % p

solutionp = hensel_lifting(fp, p, 6, basep)
assert (solutionp[0] ** 2) % (p**6) == YSQ % (p**6)
assert (solutionp[1] ** 2) % (p**6) == YSQ % (p**6)

P.<tq> = PolynomialRing(Zmod(q ** 5), implementation='NTL')
fq = tq**2 - YSQ
qq = sqrt(YSQ % q, q)
baseq = [qq, q - qq]
assert baseq[0] ** 2 % q == YSQ % q
assert baseq[1] ** 2 % q == YSQ % q
solutionq = hensel_lifting(fq, q, 5, baseq)
assert (solutionq[0] ** 2) % (q**5) == YSQ % (q**5)
assert (solutionq[1] ** 2) % (q**5) == YSQ % (q**5)


P.<tr> = PolynomialRing(Zmod(r ** 63), implementation='NTL')
fr = tr**2 - YSQ
rr = sqrt(YSQ % r, r)
baser = [rr, r - rr]
assert baser[0] ** 2 % r == YSQ % r
assert baser[1] ** 2 % r == YSQ % r
solutionr = hensel_lifting(fr, r, 63, baser)
assert (solutionr[0] ** 2) % (r**63) == YSQ % (r**63)
assert (solutionr[1] ** 2) % (r**63) == YSQ % (r**63)

for ppp, qqq, rrr in product(solutionp, solutionq, solutionr):
    x = crt([ppp, qqq, rrr], [p**6, q**5, r**63])
    assert (x**2 - YSQ) % (p**6 * q**5 * r**63) == 0
    flag = l2b(x)
    if b"CCTF" in flag:
        print(flag)
        exit()
    # CCTF{8E4uTy_0f_L1f7iN9_cOm3_Up!!}
