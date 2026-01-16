from Crypto.Util.number import getPrime, bytes_to_long
from random import randrange

FLAG = b"blahaj{REDACTED}"
FLAG = bytes_to_long(FLAG)

p, q = getPrime(512), getPrime(512)
n = p*q
e = 65537
d = pow(e, -1, (p-1)*(q-1))
print(f"{n = }")
print(f"{e = }")
print(f"c = {pow(FLAG, e, n)}")

print("I'm feeling nice, so I'll give you a hint.")

b = 512//3+1
lower = (1<<b)-1
middle = lower<<b
upper = middle<<b
m0 = p & lower
m1 = p & middle
m2 = p & upper

# Generate random x0, x1, and x2
x0, x1, x2 = [randrange(n) for _ in range(3)]
print(f"{x0 = }")
print(f"{x1 = }")
print(f"{x2 = }")
# You should choose which message you want to receive, and generate
# a random k. Then, calculate v = x_b + k^e and send it to me
v = int(input("v? "))
# One of these will be equal to your k, while the other will effectively
# be a random value
k0 = pow(v-x0, d, n)
k1 = pow(v-x1, d, n)
k2 = pow(v-x2, d, n)
# Subtract your value of k from the corresponding c to get the original
# message. You should get no information about the other message, and I
# won't know which one you chose. OT protocol complete!
c0 = m0 + k0
c1 = m1 + k1
c2 = m2 + k2
print(f"{c0 = }")
print(f"{c1 = }")
print(f"{c2 = }")
print("Bye!")