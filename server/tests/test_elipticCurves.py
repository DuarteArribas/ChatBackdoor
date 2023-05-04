import server.src
import unittest
from server.src.elipticCurves import *

class TestElipticCurves(unittest.TestCase):
  def test_sum(self):
    ec = ElipticCurves()
    print(ec.sum(ec.G,ec.G))

if __name__ == '__main__':
  unittest.main()