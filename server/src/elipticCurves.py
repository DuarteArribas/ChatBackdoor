class ElipticCurves:
  def __init__(self):
    """Initialize the Eliptic Curves parameters (P-256)."""
    self.a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
    self.b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    self.p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    self.n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    self.h = 0x1
    self.G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
    
  def sum(self,p1,p2):
    if p1[0] == p2[0]:
      if p1[1] == p2[1]:
        return self.doublePoint(p1)
      return (None,None)
    s = ((p2[1] - p1[1]) * self.modInverse( p2[0] - p1[0] + self.p, self.p )) % self.p
    x3 = ((s * s) - p1[0] - p2[0]) % self.p
    y3 = ((s * (p1[0] - x3)) - p1[1]) % self.p
    return (x3,y3)
  
  def doublePoint(self,p):
    s = ((3 * (p[0] * p[0])) + self.a ) * (self.modInverse(2 * p[1], self.p)) % self.p
    x3 = (s * s - p[0] - p[0]) % self.p
    y3 = (s * (p[0] - x3) - p[1]) % self.p
    return (x3,y3)
  
  def extended_gcd(self,aa,bb):
    """Greatest common denominator"""
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)
  
  def modInverse(self, a, n):
    """This function calculates the inverse of a modulo n"""
    g, x, y = self.extended_gcd(a, n)
    if g != 1:
        raise ValueError
    return x % n
  
  
  