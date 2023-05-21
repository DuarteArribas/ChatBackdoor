import random
import sympy

class ZeroKnowledgeProtocol:
    # Constructor
    def __init__(self):
        # Prime number P
        self.P = None
        # Prime number Q
        self.Q = None
        # Generator B
        self.B = None
        # Security parameter t
        self.t = None

    # Function to generate B
    '''
    Parameters:
        None

    Returns:
        B - generator B

    Conditions:
        alpha must be a possible generator of P
        With the above condition met, generator can be calculated as B = alpha**((P - 1) // Q) mod P
    '''
    def generate_B(self,P,Q):
        # Generate B
        alpha = random.choice(self.possible_generators_P(P))
        return pow(alpha, (P - 1) // Q,P)
        
    # Function that gets possible generators of a prime number p
    # This represents the set of numbers where each of which can be the number a in the protocol
    # Link taken from: https://asecuritysite.com/principles_pub/g_pick?val1=41
    '''
    Parameters:
        p - prime number

    Returns:
        res - list of possible generators of p

    Conditions:
        p must be a prime number
    '''
    def possible_generators_P(self,p):
        r = set(range(1, p))
        res = []
        for i in r:
            gen = set()
            for x in r:
                gen.add(pow(i,x,p))
            if gen == r:
                res.append(i)
                if (len(res)>10): break
        return res
    
    # Function to calculate the prime number Q
    '''
    Parameters:
        number - number to calculate the next prime number

    Returns:
        prime - next prime number

    Conditions:
        number must be a prime number
        Q must be greater than the number sent as parameter
    '''
    def calculate_Q(self,number):
        prime = number
        while True:
            prime += 1
            if sympy.isprime(prime):
                return prime


    # Function to calculate the prime number P
    '''
    Parameters:
        Q - prime number

    Return:
        number - prime number P

    Conditions:
        P must be a prime number
        P must be greater than Q
        P is an adequate value if P - 1 is divisible by Q which means that (P - 1) % Q == 0

    '''
    def calculate_P(self,Q):
        number = Q
        while True:
            number += 1
            if sympy.isprime(number) and (number - 1) % Q == 0:
                return number