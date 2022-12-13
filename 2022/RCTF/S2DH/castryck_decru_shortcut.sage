import time
from itertools import product
from helpers import possibly_parallel, supersingular_gens, fast_log3

load('richelot_aux.sage')
load('uvtable.sage')
load('speedup.sage')

# ===================================
# =====  ATTACK  ====================
# ===================================


def CastryckDecruAttack(E_start, P2, Q2, EB, PB, QB, two_i, num_cores=1):
    tim = time.time()

    skB = [] # TERNARY DIGITS IN EXPANSION OF BOB'S SECRET KEY

    # gathering the alpha_i, u, v from table
    expdata = [[0, 0, 0] for _ in range(b-3)]
    for i in range(b%2, b-3, 2):
        index = (b-i) // 2
        row = uvtable[index-1]
        if row[1] <= a:
            expdata[i] = row[1:4]

    # gather digits until beta_1
    bet1 = 0
    while not expdata[bet1][0]:
        bet1 += 1
    bet1 += 1

    ai,u,v = expdata[bet1-1]

    print(f"Determination of first {bet1} ternary digits. We are working with 2^{ai}-torsion.")

    bi = b - bet1
    alp = a - ai

    @possibly_parallel(num_cores)
    def CheckGuess(first_digits):
        print(f"Testing digits: {first_digits}")

        scalar = sum(3^k*d for k,d in enumerate(first_digits))
        tauhatkernel = 3^bi * (P3 + scalar*Q3)

        tauhatkernel_distort = u*tauhatkernel + v*two_i(tauhatkernel)

        C, P_c, Q_c, chainC = AuxiliaryIsogeny(bet1, u, v, E_start, P2, Q2, tauhatkernel, two_i)
        # We have a diagram
        #  C <- Eguess <- E_start
        #  |    |
        #  v    v
        #  CB-> EB
        split = Does22ChainSplit(C, EB, 2^alp*P_c, 2^alp*Q_c, 2^alp*PB, 2^alp*QB, ai)
        if split:
            Eguess, _ = Pushing3Chain(E_start, tauhatkernel, bet1)

            chain, (E1, E2) = split
            # Compute the 3^b torsion in C
            P3c = chainC(P3)
            Q3c = chainC(Q3)
            # Map it through the (2,2)-isogeny chain
            if E2.j_invariant() == Eguess.j_invariant():
                CB, index = E1, 0
            else:
                CB, index = E2, 1
            def apply_chain(c, X):
                X = (X, None) # map point to C x {O_EB}
                for f in c:
                    X = f(X)
                return X[index]
            print("Computing image of 3-adic torsion in split factor CB")
            P3c_CB = apply_chain(chain, P3c)
            Q3c_CB = apply_chain(chain, Q3c)

            Z3 = Zmod(3^b)
            # Determine kernel of the 3^b isogeny.
            # The projection to CB must have 3-adic rank 1.
            # To compute the kernel we choose a symplectic basis of the
            # 3-torsion at the destination, and compute Weil pairings.
            CB.set_order((p+1)^2, num_checks=1) # keep sanity check
            P_CB, Q_CB = supersingular_gens(CB)
            P3_CB = ((p+1) / 3^b) * P_CB
            Q3_CB = ((p+1) / 3^b) * Q_CB
            w = P3_CB.weil_pairing(Q3_CB, 3^b)
            # Compute kernel
            for G in (P3_CB, Q3_CB):
                xP = fast_log3(P3c_CB.weil_pairing(G, 3^b), w)
                xQ = fast_log3(Q3c_CB.weil_pairing(G, 3^b), w)
                if xQ % 3 != 0:
                    sk = int(-Z3(xP) / Z3(xQ))
                    return sk

            return True

    guesses = [ZZ(i).digits(3, padto=bet1) for i in range(3^bet1)]

    for result in CheckGuess(guesses):
        ((first_digits,), _), sk = result
        if sk is not None:
            print("Glue-and-split! These are most likely the secret digits.")
            bobskey = sk
            break

    # Sanity check
    bobscurve, _ = Pushing3Chain(E_start, P3 + bobskey*Q3, b)
    found = bobscurve.j_invariant() == EB.j_invariant()

    if found:
        print(f"Bob's secret key revealed as: {bobskey}")
        print(f"In ternary, this is: {Integer(bobskey).digits(base=3)}")
        print(f"Altogether this took {time.time() - tim} seconds.")
        return bobskey
    else:
        print("Something went wrong.")
        print(f"Altogether this took {time.time() - tim} seconds.")
        return None
