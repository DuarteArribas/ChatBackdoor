import random
from sympy import isprime
from Crypto.Hash import SHA512
from Crypto.Hash          import SHA512
from Crypto.Cipher        import AES
from Crypto.Util.Padding  import pad
from Crypto.PublicKey     import RSA
from Crypto.PublicKey     import ElGamal
from Crypto.Hash          import HMAC, SHA512
from Crypto.Signature     import pkcs1_15
from Crypto.Util.Padding import unpad

def generateRSAKeypair():
  p = generatePrimeNumber()
  q = generatePrimeNumber()
  phi_N = (p - 1) * (q - 1)
  e = 65537
  d = calculatePrivateExponent(e,phi_N)
  return p,q,e,d

def generatePrimeNumber():
  while True:
    num = random.randint(10**250,10**251)
    if isprime(num):
      return num

def calculatePrivateExponent(e,phi_N):
  def extendedGcd(a,b):
    if b == 0:
      return a, 1, 0
    else:
      d, x, y = extendedGcd(b, a % b)
      return d, y, x - (a // b) * y
  _, d, _ = extendedGcd(e, phi_N)
  d %= phi_N
  if d < 0:
    d += phi_N
  return d

def calculateDFromParams(p,q,e):
    phi_N = (p - 1) * (q - 1)
    def extendedGcd(a, b):
      if b == 0:
        return a, 1, 0
      else:
        d, x, y = extendedGcd(b, a % b)
        return d, y, x - (a // b) * y
    _, d, _ = extendedGcd(e, phi_N)
    d %= phi_N
    if d < 0:
      d += phi_N
    return d

def calculateRSADigitalSignature(msg,rsaPrivateKey):
    msgHash = SHA512.new(msg)
    signer = pkcs1_15.new(rsaPrivateKey)
    return signer.sign(msgHash)

def verifyRSADigitalSignature(msg,rsaSig,rsaPublicKey):
  msgHash = SHA512.new(msg)
  verifier = pkcs1_15.new(rsaPublicKey)
  try:
    verifier.verify(msgHash,rsaSig)
    return True
  except (ValueError,TypeError):
    return False

p,q,e,d = generateRSAKeypair()
N = p * q
print(f"p: {p}")
print(f"q: {q}")
print(f"q: {N // p}")
print(f"e: {e}")
print(f"d: {d}")
d = calculateDFromParams(p,q,e)
print(f"d: {d}")
sig = calculateRSADigitalSignature(b"arroz",RSA.construct((N,e,d,p,q)))
print(sig)
print(verifyRSADigitalSignature(b"arbroz",sig,RSA.construct((N,e))))

