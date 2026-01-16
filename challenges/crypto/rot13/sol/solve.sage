from pwn import *

p = remote("127.0.0.1", 1337)

for _ in range(3):
    exec(p.recvline().strip())
p.recvline()
for _ in range(3):
    exec(p.recvline().strip())

P.<x> = Zmod(n)[]

v = P(x0+x1)/2
p.recvuntil(b"v? ")
p.sendline(str(v).encode())

for _ in range(3):
    exec(p.recvline().strip())

f = (2^342*x+c0+c1).monic()
p_msb = f.small_roots(X=2^170, beta=0.45)[0]
p = ZZ(2^342*p_msb+c0+c1)
assert n % p == 0
q = n/p

from Crypto.Util.number import long_to_bytes
print(long_to_bytes(pow(c, pow(e, -1, (p-1)*(q-1)), n)))