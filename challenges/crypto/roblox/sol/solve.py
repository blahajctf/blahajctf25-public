from pwn import remote
from z3 import Solver, BitVec
from tqdm import tqdm
from time import time

SZ = 48
BLKSZ = SZ * 3 // 8
WORD = 2**SZ - 1
rol = lambda x, r: ((x << r) | (x >> (SZ - r))) & WORD
ror = lambda x, r: ((x >> r) | (x << (SZ - r))) & WORD

NROUNDS = SZ // 4
DELTA = [0x123456789a, 0x00deadbeef, 0x4141414141]

def key_schedule_128(key):
    T = [int.from_bytes(key[i * (SZ // 8) : (i + 1) * (SZ // 8)], "little") for i in range(3)]
    rks = []
    for i in range(NROUNDS):
        t0 = rol(DELTA[i % 3], i & (SZ - 1))
        t1 = rol(DELTA[i % 3], (i + 1) & (SZ - 1))
        t2 = rol(DELTA[i % 3], (i + 2) & (SZ - 1))
        T[0] = rol((T[0] + t0) & WORD, 2)
        T[1] = rol((T[1] + t1) & WORD, 3)
        T[2] = rol((T[2] + t2) & WORD, 5)
        rks.append([T[0], T[1], T[2], T[1]])
    return rks

def round(state, rk):
    x0, x1, x2 = state
    state[0] = rol(((x0 ^ rk[0]) + (x1 ^ rk[1])) & WORD, 13)
    state[1] = ror(((x1 ^ rk[2]) - (x2 ^ rk[3])) & WORD, 11)
    state[2] = x0

def encrypt(pt, key):
    rk = key_schedule_128(key)
    state = [int.from_bytes(pt[i:i + SZ // 8], "little") for i in range(0, BLKSZ, SZ // 8)]
    for r in rk:
        round(state, r)
    return b"".join(int(w).to_bytes(SZ // 8, "little") for w in state)

b2l = lambda x:[int.from_bytes(x[j:j + (SZ // 8)],'little') for j in range(0, BLKSZ, SZ // 8)]


R = remote("127.0.0.1", 20001)
R.recvuntil(b"Sample Plaintext-Ciphertext Pair:\n")
pt, ct = [bytes.fromhex(i) for i in eval(R.recvline().rstrip().decode())]
A0, A1, A2 = b2l(ct)
T32 = BitVec("T32", SZ)

def encrypt_fault(R, pt, fault_round, word_idx):
    R.recvuntil(b"Enter Option (Faultless = 0, Fault = 1)\n>> ")
    R.sendline(b"1")
    R.recvuntil(b"Enter plaintext\n>> ")
    R.sendline(pt.hex().encode())
    R.recvuntil(b"Enter fault_round, word_idx\n>> ")
    R.sendline(f"{fault_round} {word_idx}".encode())
    R.recvuntil(b">>")
    return bytes.fromhex(R.recvline().rstrip().decode())


def reverse_key_schedule_128(last_rk, one_step=False):
    T = [last_rk[0], last_rk[1], last_rk[2]]
    for i in reversed(range(NROUNDS)):
        d = DELTA[i % 3]
        t0 = rol(d, i & (SZ - 1))
        t1 = rol(d, (i + 1) & (SZ - 1))
        t2 = rol(d, (i + 2) & (SZ - 1))
        T[2] = (ror(T[2], 5) - t2) & WORD
        T[1] = (ror(T[1], 3) - t1) & WORD
        T[0] = (ror(T[0], 2) - t0) & WORD
        if one_step:
            break 
    return T


def solve_T0(cts):
    S = Solver()
    for c1 in cts:
        B0,_,B2 = b2l(c1)
        res = (ror(A0, 13) - ror(B0, 13)) % 2**SZ
        S.add((A2 ^ T32) - (B2 ^ T32) == res)
    sols = []
    while str(S.check()) == 'sat':
        sols.append(int(str(S.model()[T32])))
        S.add(T32 != sols[-1])
    return sols


def solve_T1(cts, u0):
    z3_Ds = []
    x0 = BitVec("x0", SZ)
    S = Solver()
    for p, c1 in enumerate(cts):
        _,B1,B2 = b2l(c1)
        z3_Ds.append(BitVec(f"D{p}", SZ))
        x0_plus_D = x0 + z3_Ds[-1]
        l0 = (rol(B1, 11) - rol(A1, 11)) % 2**SZ
        l1 = (ror(B2, 13) - ror(A2, 13)) % 2**SZ
        S.add(l0 == (x0 ^ T32) - (x0_plus_D ^ T32))
        S.add(l1 == (x0_plus_D ^ u0) - (x0 ^ u0))
    sols = []
    while str(S.check()) == 'sat':
        sols.append(int(str(S.model()[T32])))
        S.add(T32 != sols[-1])
    return sols


def solve_T2(cts, x1, t0, t1):
    S = Solver()
    for c1 in cts:
        B0,B1,B2 = b2l(c1)
        x1_plus_D = ((ror(B0, 13) - (B2 ^ t0)) % 2**SZ) ^ t1
        res = (rol(B1, 11) - rol(A1, 11)) % 2**SZ
        S.add(res == (x1_plus_D ^ T32) - (x1 ^ T32))
    sols = []
    while str(S.check()) == 'sat':
        sols.append(int(str(S.model()[T32])))
        S.add(T32 != sols[-1])
    return sols


def solve_key():

    CT_0s = [encrypt_fault(R, pt, NROUNDS-1, 0) for _ in range(4)]
    CT_1s = [encrypt_fault(R, pt, NROUNDS-2, 0) for _ in range(4)]
    CT_2s = [encrypt_fault(R, pt, NROUNDS-1, 1) for _ in range(4)]
    t0s = solve_T0(CT_0s)
    print(f"[DEBUG] {len(t0s) = }")
    
    for t0 in tqdm(t0s):

        u0 = reverse_key_schedule_128([t0, 0, 0], True)[0]
        t1s = solve_T1(CT_1s, u0)

        for t1 in t1s:
            
            x1 = (ror(A0, 13) - (A2 ^ t0)) % 2**SZ ^ t1
            t2s = solve_T2(CT_2s, x1, t0, t1)

            for t2 in t2s:

                last_rk = [t0, t1, t2, t1]
                init_key = reverse_key_schedule_128(last_rk)
                key = b''.join(k.to_bytes(SZ // 8, 'little') for k in init_key)

                if encrypt(pt, key) == ct:
                    print("\nFound!")
                    print(f"{key = }")
                    return key

START = time()
key = solve_key()
R.sendline(key.hex().encode())
print(f"Time taken: {time() - START} seconds")
R.interactive()
"""
[x] Opening connection to 127.0.0.1 on port 20001
[x] Opening connection to 127.0.0.1 on port 20001: Trying 127.0.0.1
[+] Opening connection to 127.0.0.1 on port 20001: Done
[DEBUG] len(t0s) = 8
 88%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████▊                | 7/8 [00:26<00:03,  3.86s/it]
Found!
key = b'\x06;&\xf6\xeaY ;,I%\xf7\xc3\xe1\xb0\xf6\x0e\x05'
 88%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████▊                | 7/8 [00:30<00:04,  4.30s/it] 
Time taken: 30.207316398620605 seconds
[*] Switching to interactive mode
Enter key:
>> blahaj{dont_w3+l0ve_d1ff3r3nt14l_analysis?!-insp1r3d_bY_Codegate2025Finals!}
[*] Got EOF while reading in interactive
[*] Interrupted
[*] Closed connection to 127.0.0.1 port 20001
"""