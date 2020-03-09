from secret import n, e, d

class DIYSig(object):
    """
    Self-made Digital Signature System
    """
    def __init__(self):
        """ Initialize and reset this instance """
        self.n = n
        self.e = e
        self.d = d

    def encsig(self, m):
        """ DIY Encrypt System """
        c = pow(m, self.e, self.n)
        h = self._hash(m)
        return c, h

    def getsig(self, c):
        """ DIY Signature """
        m = pow(c, self.d, self.n)
        h = self._hash(m)
        return h

    def _hash(self, m):
        """ DIY Hash Function """
        H = 0xcafebabe
        M = m
        # Stage 1
        while M > 0:
            H = (((H << 5) + H) + (M & 0xFFFFFFFF)) & 0xFFFFFFFF
            M >>= 32
        # Stage 2
        M = H
        while M > 0:
            H = ((M & 0xFF) + (H << 6) + (H << 16) - H) & 0xFFFFFFFF
            M >>= 8
        # Stage 3
        H = H | 1 if m & 1 else H & 0xfffffffe
        return H

    def pubkey(self):
        """ Public Key """
        return self.n, self.e
