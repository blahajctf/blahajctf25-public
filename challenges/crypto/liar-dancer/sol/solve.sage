from pwn import *
from Crypto.Util.number import long_to_bytes

ps = [28901765778039325343184104246369870352446458921, 28901765793509048740070714254875369198685166041, 28901765798390236255096626685767850989220044289, 28901765830501463790970229598779944701468376081, 28901765830501463790970229598779944701468376081, 28901765881520747173762334004799419947029338409, 28901765922272471437990065473832649131687766801] # from find.sage

a = []
y = []

for prime in ps:
    p = remote("127.0.0.1", 1337)
    p.sendlineafter(b"> ", str(prime).encode())
    a.append(int(p.recvline().strip().split(b" = ")[1]))
    y.append(int(p.recvline().strip().split(b" = ")[1]))

mods = [Zmod(p)(a).multiplicative_order() for p, a in zip(ps, a)]
res = [Zmod(p)(y).log(a) for p, y, a in zip(ps, y, a)]
print(long_to_bytes(int(crt(res, mods))))