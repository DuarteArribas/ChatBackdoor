import hashlib

class Chap:
  """Implements the CHAP authentication protocol."""
  @staticmethod
  def getChapChallenge(nonce,secret):
    """Get the CHAP challenge.
    
    Parameters
    ----------
    nonce : int
      The nonce to be hashed
    secret : str
      The secret to be hashed
    
    Return
    ----------
    str
      The hashed challenge
    """
    preChallenge = nonce + secret
    challenge = hashlib.sha512(preChallenge.encode("utf-8"))
    challenge.digest()
    return challenge.hexdigest()