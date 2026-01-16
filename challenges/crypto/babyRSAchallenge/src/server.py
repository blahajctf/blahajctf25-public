from Crypto.Util.number import getPrime, bytes_to_long
import random

FLAG = "blahaj{meanwhile-there-was-that-other-one-in-2024_LNC...}"

m = bytes_to_long(random.randbytes(64))
try:
  p = int(input("Enter your prime number!\n>> "))
except EOFError:
  exit(0)

q = getPrime(512)
r = getPrime(512)
n = p*q*r
e = 65537
c = pow(m, e, n)
print("c =", c)
print("n =", n)

try:
  _m = int(input("Enter secret\n>> "))
except EOFError:
  exit(0)

if _m == m:
  print(FLAG)
else:
  print("hmm...what could you be missing?")