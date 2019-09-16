"""
supercurve.py

    An implementation of a weak elliptic curve over a prime field in standard Weirstrauss form:
        y^2 = x^3 + ax + b

    Derived from: https://github.com/andreacorbellini/ecc/blob/master/logs/common.py
"""

class SuperCurve:

    def __init__(self, field, order, a, b, g):
        """
        a, b = coefficients
        g = base point
        """
        self.field = field
        self.order = order

        self.a = a
        self.b = b
        self.g = g

        assert pow(2, field - 1, field) == 1
        assert (4 * a * a * a + 27 * b * b) % field != 0

    def __str__(self):
        return "a = {}\nb = {}\np = {}\nn = {}".format(self.a, self.b, self.field, self.order)

    def is_on_curve(self, point):
        if point is None:
            return True

        (x, y) = point
        return (y * y - x * x * x - self.a * x - self.b) % self.field == 0

    def add(self, p1, p2):
        assert self.is_on_curve(p1)
        assert self.is_on_curve(p2)

        if p1 is None:
            return p2
        if p2 is None:
            return p1

        (x1, y1) = p1
        (x2, y2) = p2

        if x1 == x2 and y1 != y2:
            return None

        if x1 == x2:
            m = (3 * x1 * x1 + self.a) * SuperCurve.inv_mod(2 * y1, self.field)
        else:
            m = (y1 - y2) * SuperCurve.inv_mod(x1 - x2, self.field)

        x3 = m * m - x1 - x2
        y3 = y1 + m * (x3 - x1)
        result = (x3 % self.field, -y3 % self.field)
        assert self.is_on_curve(result)
        return result

    def double(self, p):
        return self.add(p, p)

    def neg(self, p):
        if p is None:
            return None

        (x, y) = p
        res = x, -y % self.field
        assert self.is_on_curve(res)
        return res

    def mult(self, scal, point):
        if scal % self.order == 0 or point is None:
            return None
        if scal < 0:
            return self.neg(self.mult(-scal, point))

        result = None
        addend = point

        while scal:
            if scal & 1:
                result = self.add(result, addend)
            addend = self.double(addend)
            scal >>= 1

        return result

    @staticmethod
    def inv_mod(n, p):
        if n == 0:
            raise Exception
        if n < 0:
            return p - SuperCurve.inv_mod(-n, p)

        s, old_s = 0, 1
        t, old_t = 1, 0
        r, old_r = p, n

        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_s - quotient * t

        gcd, x, y = old_r, old_s, old_t

        assert gcd == 1
        assert (n * x) % p == 1
        return x % p


curve = SuperCurve(
    field = 14753, order = 14660,
    a = 1, b = -1, g = (1, 1),
)
