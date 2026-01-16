import os
os.environ["TERM"] = "xterm-256color"
os.environ["TERMINFO"] = "/usr/share/terminfo"

from sage.all import GF, EllipticCurve, PolynomialRing
from hashlib import sha256
from pwn import remote
import itertools

p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

# https://ask.sagemath.org/question/74403/points-must-be-on-same-curve-ate_pairing-bls12-381/
Fp = GF(p)
F12 = GF(p**12, name='a'); a = F12.gens()[0]
RF = PolynomialRing(F12, name='T'); T = RF.gens()[0]
j = (T**2 + 1).roots(ring=RF, multiplicities=0)[0]

E0 = EllipticCurve(Fp, [0, 4])
E1 = EllipticCurve(F12, [0, 4])
E2 = EllipticCurve(F12, [0, 4*(j+1)])
phi = E2.isomorphism_to(E1)             # onoes this is an isogeny

x1 = 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
y1 = 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1
G1 = E1(x1, y1)

x2 = ( 0x024AA2B2F08F0A91260805272DC51051C6E47AD4FA403B02B4510B647AE3D1770BAC0326A805BBEFD48056C8C121BDB8
       + 0x13E02B6052719F607DACD3A088274F65596BD0D09920B61AB5DA61BBDC7F5049334CF11213945D57E5AC7D055D042B7E * j )
y2 = ( 0x0CE5D527727D6E118CC9CDC6DA2E351AADFD9BAA8CBDD3A76D429A695160D12C923AC9CC3BACA289E193548608B82801
       + 0x0606C4A02EA734CC32ACD2B02BC28B99CB3E287E85A763AF267492AB572E99AB3F370D275CEC1DA1AAA9075FF05F79BE * j )
G2 = E2(x2, y2)

def H(m):
    h = int(sha256(m).hexdigest(), 16) % r
    return h * G1

rem = remote('crypto-baconlettucesalami.chals.blahaj.sg', 30044, level='debug')

rem.recvuntil(b'My public key is ')
line = eval(rem.recvline().rstrip().decode())
x_A = sum([j*a**i for i,j in enumerate(line)])
rem.recvuntil(b'oo ok, mine\'s ')
line = eval(rem.recvline().rstrip().decode())
x_B = sum([j*a**i for i,j in enumerate(line)])
rem.recvuntil(b'[You] ')
line = eval(rem.recvline().rstrip().decode())
x_C = sum([j*a**i for i,j in enumerate(line)])
print(x_A)
print(x_B)
print(x_C)

p_A, p_B, p_C = [E2.lift_x(i) for i in [x_A, x_B, x_C]]

rem.sendline(b'1')
rem.sendline(b'We\'ll give the flag entirely to Charlie')

p_C_ = p_C - p_A - p_B
msg = str(p_C_).encode()

rem.sendline(b'3')
rem.sendline(str(p_C_.x().list())[1:-1].encode())
rem.sendline(str(p_C_.y().list())[1:-1].encode())

rem.sendline(b'4')
rem.sendline(b'0')
rem.interactive()
"""
> [Alice] Alright, its all up to you now. Give it the pointer of our shared signatures!
[VAULT] Enter sig id
> [VAULT] ur_flag = blahaj{sandwich-f0rgery}
[Alice] wait, i got nothing?!?!
[Bob] what the... Charlie you SNAKEEEEEEEEE >:((((((
[*] Got EOF while reading in interactive
$
[*] Interrupted
[*] Closed connection to crypto-baconlettucesalami.chals.blahaj.sg port 30044
"""