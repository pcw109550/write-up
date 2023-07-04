class GF: # Polynomial = x^8 + x^4 + x^3 + x^1 + x^0
    def __init__(self, val):
        self.val = val
    
    def __add__(self, other):
        return GF(self.val ^ other.val)

    def __sub__(self, other):
        return GF(self.val ^ other.val)

    def __mul__(self, other):
        a = self.val
        b = other.val
        ret = 0
        for i in range(8):
            if (b & 1): 
                ret ^= a
            a = (a << 1)
            if a & 0x100:
                a = (a & 0xff) ^ 0x1B
            b >>= 1
        return GF(ret)
    
    def lrotate(self, other):
        return GF(((self.val << other) & 0xff) | (self.val >> (8-other)))

    def __rshift__(self, other):
        return GF((self.val >> other) & 0xff)

    def __eq__(self, other):
        return self.val == other.val

    def __str__(self):
        return hex(self.val)[2:].zfill(2)
        
    def __int__(self):
        return self.val
    
