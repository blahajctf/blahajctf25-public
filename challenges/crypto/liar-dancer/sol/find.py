from Crypto.Util.number import isPrime

x = 281474976710677
while True:
    p1 = 6*x + 1
    p2 = 6*2*x + 1
    p3 = 6*3*x + 1
    pt = 36*x**2 + 11*x + 1
    if all(isPrime(i) for i in [p1, p2, p3, pt]):
        assert p1*p2*p3 == 36*x*pt+1
        print(p1*p2*p3)
    x += 1