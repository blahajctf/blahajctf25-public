import random
from math import gcd
from secrets import vals

p = 2**127-1

for i in range(5):
    print(f"[ {i+1} / 5 ]")
    s = random.choice(vals)
    print(f"🐱 = {s}")
    try:
        a = int(input("😾 = "))
        b = int(input("😿 = "))
        c = int(input("🙀 = "))
    except EOFError:
        exit(0)
    if not all(abs(i) > p for i in [a, b, c]):
        print("😿😿😿")
        break
    if gcd(a, b) != 1 or gcd(b, c) != 1 or gcd(c, a) != 1:
        print("😿😿😿")
        break
    numer = a**3 + 3*a**2*b + 2*a*b**2 + b**3 + 2*a**2*c + 6*a*b*c + 3*b**2*c + 3*a*c**2 + 2*b*c**2 + c**3
    denom = a**2*b + a*b**2 + a**2*c + 2*a*b*c + b**2*c + a*c**2 + b*c**2
    if numer - s*denom:
        print("😿😿😿")
        break
    print("😸😸😸\n")
else:
    print("😽😽😽")
    print("blahaj{REDACTED}")