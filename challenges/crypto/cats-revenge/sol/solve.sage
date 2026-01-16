from pwn import *

p = remote("127.0.0.1", 1337)

for _ in range(5):
    p.recvuntil("🐱 = ".encode())
    s = int(p.recvline()) # replace this with whatever you get from the server

    P.<x, y, z> = ProjectiveSpace(QQ, 2)

    numer = x^3 + 3*x^2*y + 2*x*y^2 + y^3 + 2*x^2*z + 6*x*y*z + 3*y^2*z + 3*x*z^2 + 2*y*z^2 + z^3
    denom = x^2*y + x*y^2 + x^2*z + 2*x*y*z + y^2*z + x*z^2 + y*z^2

    f = EllipticCurve_from_cubic(numer - s*denom, (1, 1, -1)).inverse()
    E = f.domain()

    G_ = G = E.gens(proof=False)[0]

    while True:
        sol = f(G)
        sol.clear_denominators()
        if all(abs(x) > 2^127-1 for x in sol):
            break
        G += G_
    for v in sol:
        p.sendline(str(v).encode())

p.interactive()