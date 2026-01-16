from random import randrange
from sympy.ntheory import factorint
from math import log2

FLAG = b"blahaj{0DoRe_0DOre_Us0_N1_0d0rE}"
FLAG = int.from_bytes(FLAG, "big")

def is_prime(x):
    for _ in range(int(log2(x))):
        a = randrange(x)
        if pow(a, x-1, x) != 1:
            return False
    return True

def is_safe(x):
    return max(f for f, _ in factorint(x-1).items()) > 2**100

try:
    p = int(input("p?\n> "))
except EOFError:
    exit(0)

if is_prime(p):
    if is_safe(p):
        a = randrange(p)
        y = pow(a, FLAG, p)
        print(f"{a = }\n{y = }")
    else:
        print("liar...")
else:
    print("liar...")