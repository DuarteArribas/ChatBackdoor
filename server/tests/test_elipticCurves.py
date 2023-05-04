import server.src
import unittest
from server.src.ellipticCurves import *

class TestElipticCurves(unittest.TestCase):
  #def test_sum(self):
  #  ec = EllipticCurves()
  #  print(ec.sum(ec.G,ec.G))
  #
  #def test_multiplyByScalar(self):
  #  ec = EllipticCurves()
  #  self.assertEqual(ec.multiplyPointByScalar(ec.G,1),(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5))
  #
  def test_generateKeys(self):
    ec = EllipticCurves()
    print(ec.generateKeys())

if __name__ == '__main__':
  unittest.main()