import secrets

class EllipticCurves:
  def __init__(self):
    """Initialize the Elliptic Curves parameters (P-256). Values taken from https://neuromancer.sk/std/nist/P-256#.
    """
    self.a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
    self.b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    self.p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    self.n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    self.h = 0x1
    self.G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
    
  def sum(self,p1,p2):
    """Execute elliptic curve sum between two points.
    
    Parameters
    ----------
    p1 : point (x, y)
      First point in the elliptic curve
    p2 : point (x, y)
      Second point in the elliptic curve

    Return
    ----------
    (x3, y3) : point (x, y)
      The summed point (or the first point, if p1 == p2)
    """
    if p1[0] == p2[0]:
      if p1[1] == p2[1]:
        # if the points have the same coordinates, return itself
        return self.doublePoint(p1)
      # if the points have the same x coordinates, but different y coordinates, return a null point
      return (None,None)
    s = ((p2[1] - p1[1]) * self.modInverse( p2[0] - p1[0] + self.p, self.p )) % self.p
    x3 = ((s * s) - p1[0] - p2[0]) % self.p
    y3 = ((s * (p1[0] - x3)) - p1[1]) % self.p
    return (x3,y3)
  
  def doublePoint(self,p):
    """Sums a point with himself in the elliptic curve.

    Parameters
    ----------
    p : point (x, y)
      Point in the elliptic curve

    Return
    ----------
    (x3, y3) : point (x, y)
      The summed point
    """
    s = ((3 * (p[0] * p[0])) + self.a ) * (self.modInverse(2 * p[1], self.p)) % self.p
    x3 = (s * s - p[0] - p[0]) % self.p
    y3 = (s * (p[0] - x3) - p[1]) % self.p
    return (x3,y3)
  
  def extended_gcd(self,aa,bb):
    """Calculate the greatest common denominator.
    
    Parameters
    ----------
    aa : int
      First number to consider
    bb : int
      Second number to consider
    
    Return
    ----------
    lastremainder : int
      Greatest common denominator
    lastx : int
      The inverse of aa
    lasty : int
      The inverse of bb
    """
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
      lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
      x, lastx = lastx - quotient*x, x
      y, lasty = lasty - quotient*y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)
  
  def modInverse(self, a, n):
    """Calculate the inverse of a module n.
    
    Parameters
    ----------
    a : int
      The number to divide for
    n : int
      The number to divide with
    
    Return
    ----------
    x % n
      Inverse module of n
    """
    g, x, y = self.extended_gcd(a, n)
    if g != 1:
        raise ValueError
    return x % n
  
  def bit_length(self,n):
    """Get the number of bits of itself.
    
    Parameters
    ----------
    n : int
      Integer number to be represented in binary
    
    Return
    ----------
    len(s) : int
      Length of the binary representation of n
    """
    s = bin(n)          # binary representation:  bin(-37) --> '-0b100101'
    s = s.lstrip('-0b') # remove leading zeros and minus sign
    return len(s)       # len('100101') --> 6
  
  def multiplyPointByScalar(self,p,n):
    """Multiply a point by a scalar value.

    Parameters
    ----------
    p : point(x, y)
      Point to be multiplied
    n : int
      Scalar
      
    Return
    ----------
    result : point (x, y)
      Multiplied point
    """
    nbits = self.bit_length(n)
    result = (p[0],p[1])
    p1 = (p[0],p[1])

    for i in range(1, nbits):
      result = self.doublePoint(p)
      bit = (n >> (nbits-i-1) ) & 1
      if bit == 1 :
        result = self.sum(p1,p)
    return result
  
  def generateKeys(self):
    """Generate a pair of Diffie-Hellman on elliptic curve keys.

    Return
    ----------
    (X, dA) : tuple
      X : point (x, y)
        Pair of keys (x: private key, y: public key)
      dA : int
        Random integer number between 1 and n - 1
    """
    dA = secrets.randbelow(self.n - 1) + 1
    X = self.multiplyPointByScalar(self.G,dA)
    return (X,dA)