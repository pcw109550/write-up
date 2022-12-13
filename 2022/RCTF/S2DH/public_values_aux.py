from sage.all import ZZ, randint

p = None

def generate_distortion_map(E):
    if E.a_invariants() != (0,6,0,1,0):
        raise NotImplementedError
    return E.isogeny(E.lift_x(ZZ(1)), codomain=E)

def generate_torsion_points(E, a, b):
    def get_l_torsion_basis(E, l):
        n = (p+1) // l
        return (n*G for G in E.gens())

    P2, Q2 = get_l_torsion_basis(E, 2**a)
    P3, Q3 = get_l_torsion_basis(E, 3**b)

    return P2, Q2, P3, Q3

def check_torsion_points(E, a, b, P2, Q2, P3, Q3):
    # Make sure Torsion points are
    # generated correctly
    infty = E(0)
    assert 2**(a-1)*P2 != infty
    assert 3**(b-1)*P3 != infty
    assert P2.weil_pairing(Q2, 2**a)**(2**(a-1)) != 1
    assert P3.weil_pairing(Q3, 3**b)**(3**(b-1)) != 1

def gen_bob_keypair(E_start, b, P2, Q2, P3, Q3):
    # generate challenge key
    bobs_key = randint(0,3**b)    
    K = P3 + bobs_key*Q3
    phi = E_start.isogeny(K, algorithm="factored")
    EB = phi.codomain()
    EB.set_order((p+1)**2, num_checks=0)

    PB, QB = phi(P2), phi(Q2)

    return bobs_key, EB, PB, QB
