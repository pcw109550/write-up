# Don't pollute the global namespace
def _do_speedup():
    # And because why not
    proof.all(False)

    # Lorenz Panny has fixed both of the below monkey patches with the tickets:
    # - https://trac.sagemath.org/ticket/34281 (Caching of the finite fields)
    # - https://trac.sagemath.org/ticket/34284 (Dimension of hyperelliptic curve)
    #
    # We should check the version of sage and if >= 9.7 skip the below patches
    from sage.misc.banner import require_version
    if not require_version(9,7):
        # Since this type gets created before we could ever hope to monkey patch the 
        # `sage.categories.fields.Fields.ParentMethods`
        # method, we'll patch it on the relevant type instead.
        # We'll patch a few different types to make sure we get the relevant things (large and small prime, extension and no extension)
        p = 2^127 - 1 # Arbitrary large prime
        to_patch = [GF(3), GF(3^2), GF(p), GF(p^2)]
        for x in to_patch:
            type(x).vector_space = sage.misc.cachefunc.cached_method(type(x).vector_space)

        # An alternative would be to replace the bytecode in 
        # `sage.categories.fields.Fields.ParentMethods.vector_space`
        # as all types share the same method, by identity
        # Something to be explored later, perhaps :)

        # No use calculating the dimension of HyperElliptic every single time
        from sage.schemes.projective.projective_subscheme import AlgebraicScheme_subscheme_projective
        AlgebraicScheme_subscheme_projective.dimension = lambda self: 1


_do_speedup()
