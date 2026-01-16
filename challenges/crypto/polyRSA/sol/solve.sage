from Crypto.Util.number import long_to_bytes, bytes_to_long

p = next_prime(2^32)
K.<x> = GF(p)[]

N = 67256387*x^16 + 3785639081*x^15 + 2243704320*x^14 + 2510382192*x^13 + 1559187120*x^12 + 1523961994*x^11 + 2440248838*x^10 + 764754967*x^9 + 4190435294*x^8 + 4065822583*x^7 + 1057162888*x^6 + 4235943041*x^5 + 988301557*x^4 + 3205679312*x^3 + 4147841349*x^2 + 2991402492*x + 493401902
e = 65537
c = 1716040029*x^15 + 1696954190*x^14 + 4053818925*x^13 + 1939649983*x^12 + 2138498341*x^11 + 1570315003*x^10 + 1612601010*x^9 + 2438663461*x^8 + 979049063*x^7 + 1638778176*x^6 + 2539855018*x^5 + 3011253693*x^4 + 74288680*x^3 + 3575879293*x^2 + 390800087*x + 2221336254

factors = [*N.factor()]
order = 1
for f, m in factors:
    d = f.degree()
    if d == 0:
        continue
    order *= (p^d-1)^m

def poly_to_bytes(x):
    m = b""
    for i in x:
        m += long_to_bytes(int(i))
    return m

d = pow(e, -1, order)
m = pow(c, d, N)
m += N*((bytes_to_long(b"blah")-m(0))/N(0))
flag = poly_to_bytes(m)
assert flag.startswith(b"blahaj{")
print(flag.decode())