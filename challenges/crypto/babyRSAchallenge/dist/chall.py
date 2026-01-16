from SECRET import FLAG
from Crypto.Util.number import getPrime, bytes_to_long
import random

m = bytes_to_long(random.randbytes(64))
p = int(input("Enter your prime number!\n>> "))
q = getPrime(512)
r = getPrime(512)
n = p*q*r
e = 65537
c = pow(m, e, n)
print("c =", c)
print("n =", n)

_m = int(input("Enter secret\n>> "))
if _m == m:
  print(FLAG)
else:
  print("hmm...what could you be missing?")