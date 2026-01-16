from sage.all import GF, EllipticCurve, randint, PolynomialRing, proof, load
from hashlib import sha256

proof.all(False)

# ===========================================================================================================
# Set up might take a while on the ncat fyi. Be Patient! Sound a ticket if nothing appears after 2-3 minutes.
# ===========================================================================================================

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
# E2 = load("E2.sobj") # slower;
# E1 = load("E1.sobj")
# E0 = ("E0.sobj")

# phi = load("phi.sobj") # faster;
phi = E2.isomorphism_to(E1)             # onoes this is an isogeny
# save(phi, "phi.sobj")

x1 = 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
y1 = 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1
G1 = E1(x1, y1)

x2 = ( 0x024AA2B2F08F0A91260805272DC51051C6E47AD4FA403B02B4510B647AE3D1770BAC0326A805BBEFD48056C8C121BDB8
       + 0x13E02B6052719F607DACD3A088274F65596BD0D09920B61AB5DA61BBDC7F5049334CF11213945D57E5AC7D055D042B7E * j )
y2 = ( 0x0CE5D527727D6E118CC9CDC6DA2E351AADFD9BAA8CBDD3A76D429A695160D12C923AC9CC3BACA289E193548608B82801
       + 0x0606C4A02EA734CC32ACD2B02BC28B99CB3E287E85A763AF267492AB572E99AB3F370D275CEC1DA1AAA9075FF05F79BE * j )
G2 = E2(x2, y2)

def KeyGen():
    sk = randint(1, r-1)
    pk = sk * G2
    return sk, pk

def H(m):
    h = int(sha256(m).hexdigest(), 16) % r
    return h * G1

def Sign(sk, m):
    σ = sk * H(m)
    return σ

def Verify(pk, m, σ):
    e0, e1 = σ.weil_pairing(phi(G2), r), H(m).weil_pairing(phi(pk), r)
    return e0 == e1

def VerifyAggregate(PK, m, Σ):
    e0, e1 = sum(Σ).weil_pairing(phi(G2), r), H(m).weil_pairing(phi(sum(PK)), r)
    return e0 == e1

FLAG = 'blahaj{sandwich-f0rgery}' # 24
assert len(FLAG) == 24

sk_A, pk_A = KeyGen()
sk_B, pk_B = KeyGen()
sk_C, pk_C = KeyGen()
PK = [pk_A, pk_B, pk_C]
SK = [sk_A, sk_B, sk_C]
SIGS = []

print(f'[Alice] Hi everyone! My public key is {pk_A.x().list()}')
print(f'[Bob] oo ok, mine\'s {pk_B.x().list()}')
print(f'[You] {pk_C.x().list()}')

while True:
    print("1. Sign message (Indiv)\n2. Sign message (Group)\n3. Change Keys (Indiv)\n4. Open The Vault (Group)")
    try:
        inp = int(input("> "))
    except EOFError:
        exit(0)

    if inp == 1:
        try:
            msg = str(input("Enter message > ")).encode()
        except EOFError:
            exit(0)

        σ = Sign(sk_C, msg)
        SIGS.append((msg, σ))
        print(f'[SERVER] Your signature: {σ.x().list()}')
    elif inp == 2:
        print("[Alice] Okay everyone, lets do this together! We will all sign 'We'll share the flag equally among ourselves', kay?")
        print("[Bob] lgtm!")
        print("[You] sure...")
        σA = Sign(sk_A, b'We\'ll share the flag equally among ourselves')
        σB = Sign(sk_B, b'We\'ll share the flag equally among ourselves')
        σC = Sign(sk_C, b'We\'ll share the flag equally among ourselves')
        SIGS.append((b'We\'ll share the flag equally among ourselves', σA, σB, σC))
        print(f'[SERVER] Alice signature: {σA.x().list()}')
        print(f'[SERVER] Bob signature: {σB.x().list()}')
        print(f'[SERVER] Your signature: {σC.x().list()}')
    elif inp == 3:
        try:
            msg = str(input("Enter public key x value separated by commas\n> ")).split(", ")
            coeffs = [Fp(int(i)) for i in msg]
            new_x = sum([j*a**i for i,j in enumerate(coeffs)])
            msg = str(input("Enter public key y value separated by commas\n> ")).split(", ")
            coeffs = [Fp(int(i)) for i in msg]
            new_y = sum([j*a**i for i,j in enumerate(coeffs)])
            pk_C = E2(new_x, new_y)
            PK[-1] = pk_C
        except EOFError:
            exit(0)
        except:
            print("Error, try again.")
    elif inp == 4:
        print("[Alice] Alright, its all up to you now. Give it the pointer of our shared signatures!")
        
        try:
            ptr = int(input("[VAULT] Enter sig id\n> "))
        except EOFError:
            exit(0)
        
        msg, sigs = SIGS[ptr][0], SIGS[ptr][1:]
        if not VerifyAggregate(PK, msg, sigs):
            print("[VAULT] UNAUTHORISED SIGNATURE.")
            print("[Bob] NOOO! YOU THREW!!! :<")
            break
        if msg == b'We\'ll share the flag equally among ourselves':
            print("[Alice] Yay! Good job guys!!!")
            print("[Bob] You did it!!! poggers")
            ur_flag = FLAG[:len(FLAG)//3]
            bob_flag = FLAG[len(FLAG)//3:2*len(FLAG)//3]
            alice_flag = FLAG[2*len(FLAG)//3:]
            print("[VAULT] ur_flag =", ur_flag)
            break
        elif msg == b'We\'ll give the flag entirely to Charlie':
            print("[VAULT] ur_flag =", FLAG)
            print("[Alice] wait, i got nothing?!?!")
            print("[Bob] what the... Charlie you SNAKEEEEEEEEE >:((((((")
            break
        else:
            print("[VAULT] Message unidentified")
            print("[Alice] ???")
            break
    else:

        break