import random
from math import gcd

can = [6, 9, 10, 13, 14, 15, 16, 17, 18, 19, 20, 21, 26, 29, 30, 31, 35, 36, 38, 40, 41, 44, 47, 51, 53, 54, 57, 62, 63, 64, 66, 67, 69, 70, 74, 76, 77, 84, 86, 87, 94, 96, 98]

p = 2**127-1

for i in range(5):
    print(f"[ {i+1} / 5 ]")
    s = random.choice(can)
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
    print("blahaj{K0ngkK0nG_30r30bU7-3uN_h4n'g4ng_w1-r0_G0y4NG'1G4_g30R30d4n1MN1D4__sorry_for_the_unintended!}")