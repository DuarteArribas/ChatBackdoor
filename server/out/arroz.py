import random
from sympy import isprime
from Crypto.PublicKey     import RSA

def generate_rsa_keypair():
    # Step 1: Generate two distinct prime numbers, p and q
    p = generate_prime_number()
    q = generate_prime_number()
    
    # Step 2: Compute the modulus N
    N = p * q
    
    # Step 3: Compute Euler's totient function of N
    phi_N = (p - 1) * (q - 1)
    
    # Step 4: Choose the public exponent e
    e = choose_public_exponent(phi_N)
    
    # Step 5: Compute the private exponent d
    d = calculate_private_exponent(e, phi_N)
    
    return p, q, e, d


def generate_prime_number():
    while True:
        # Generate a random number within a suitable range
        num = random.randint(10**307, 10**308)  # Adjust the range as needed
        
        if isprime(num):
            return num


def choose_public_exponent(phi_N):
    # Commonly used public exponent is 65537
    # You can modify this function to select a different e if desired
    return 65537


def calculate_private_exponent(e, phi_N):
    # Extended Euclidean Algorithm to calculate modular inverse
    def extended_gcd(a, b):
        if b == 0:
            return a, 1, 0
        else:
            d, x, y = extended_gcd(b, a % b)
            return d, y, x - (a // b) * y
    
    _, d, _ = extended_gcd(e, phi_N)
    
    # Ensure d is positive
    d %= phi_N
    if d < 0:
        d += phi_N
    
    return d

def calculate_private_exponent2(p, q, n, e):
    # Compute Euler's totient function of N
    phi_N = (p - 1) * (q - 1)
    
    # Extended Euclidean Algorithm to calculate modular inverse
    def extended_gcd(a, b):
        if b == 0:
            return a, 1, 0
        else:
            d, x, y = extended_gcd(b, a % b)
            return d, y, x - (a // b) * y
    
    _, d, _ = extended_gcd(e, phi_N)
    
    # Ensure d is positive
    d %= phi_N
    if d < 0:
        d += phi_N
    
    return d

p,q,e,d = generate_rsa_keypair()
key = RSA.construct((p * q,e,d,p,q))
print(key.exportKey())
print(f"first d: {d}")
print(f"second d: {calculate_private_exponent2(p,q,p*q,e)}")
print(d == calculate_private_exponent2(p,q,p*q,e))
