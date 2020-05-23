import Crypto.Util, Crypto.Random
import random
import math

def getAllPrimes(n):
    res = []
    for i in range(2,n):
        if all(i%j!=0 for j in range(2,int(math.sqrt(i))+1)):
           res.append(i)
    return res

def generatePrimeOfGivenLength(n):
    return Crypto.Util.number.getPrime(n)

def is_generator(h, q_f, p):
    flag = 0
    for q_i in q_f:
        if pow(h, q_i, p) == 1:
            flag = 1
            break
    if flag==0:
        return True
    else:
        return False

def findGenerator(p):
    primes = getAllPrimes(p-1)
    q = p-1
    q_f = [q//prime for prime in primes if q % prime == 0]
    for h in range(1, q):
        if not is_generator(h, q_f, p):
            pass
        else:
            return h

class Signer:
    def __init__(self, x, p, g):
        self.x = x
        self.p = p
        self.g = g
        self.y = pow(g, x, p)

    def get_y(self):
        return self.y

    def CRHF(self, x1, x2, x3):
        k1 = 2
        k2 = 3
        z = pow(self.g, k1, self.p)
        z1 = pow(self.g, k2, self.p)

        return (pow(self.g, x1, self.p) * pow(z, x2, self.p) * pow(z1, x3, self.p)) % self.p

    def signature(self, m):
        r = random.randint(0, self.p - 1)
        a1 = pow(m, self.x, self.p)
        a2 = pow(m, r, self.p)
        a3 = pow(self.g, r, self.p)
        c = self.CRHF(a1, a2, a3)
        s = c * self.x + r
        return [s, a1, a2, a3]

class Verifier:
    def __init__(self, y, p, g):
        self.y = y
        self.p = p
        self.g = g

    def CRHF(self, x1, x2, x3):
        k1 = 2
        k2 = 3
        z = pow(self.g, k1, self.p)
        z1 = pow(self.g, k2, self.p)

        return (pow(self.g, x1, self.p) * pow(z, x2, self.p) * pow(z1, x3, self.p)) % self.p

    def verify(self, cipeher, m):
        c = self.CRHF(cipeher[1], cipeher[2], cipeher[3])
        s = cipeher[0]

        cond1 = (pow(self.g, s, self.p) == (pow(self.y, c, self.p) * cipher[3]) % self.p)
        cond2 = (pow(m, s, self.p) == (pow(cipher[1],c, self.p) * cipher[2]) % self.p)
        if cond1 and cond2:
            return "Verified."
        else:
            return "Verification failed"

P = generatePrimeOfGivenLength(16)
g = findGenerator(P)
print("Prime :", P)
print("Generator :", g)

x = int(input("Private key of signer (x) : "))

S = Signer(x, P, g)
y = S.get_y()
V = Verifier(y, P, g)

m = int(input("Message to be sent (m) : "))
cipher = S.signature(m)
print("Signer sends Message: {}, Ciphertext: {}".format(m,cipher))
print(V.verify(cipher, m))