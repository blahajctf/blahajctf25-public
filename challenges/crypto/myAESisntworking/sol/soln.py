
iv = bytes.fromhex("a74286dc53a7e51a19de722b1e22a9bd")
pt = bytes.fromhex("03a4113b96b860e0fafd6a00c3583f1712c0ba08dd46547ddb87f3d61f838a323ea10466a8b86ef2ecd14642a5691935")
ct = bytes.fromhex("220c4c94a435fe05c4432802208cc612fb8fe3d29a75f089977c401b8f28c4d75fb9a2c30d1b99275e8188917c4d134e")
p0, p1, p2 = pt[:16], pt[16:32], pt[32:48]
c0, c1, c2 = ct[:16], ct[16:32], ct[32:48]

# Let F0, F1, F2 be the flag bytes
# Let f() be the AES ECB encryption function. We then have
# C0 = f(F0 ^ IV)
# C1 = f(F1 ^ C0)
# C2 = f(F2 ^ C1)
# and after starring at the CBC block diagram, we may deduce
# f(P0 ^ IV) = C2 = f(F2 ^ C1) ==> F2 = P0 ^ IV ^ C1
# f(P1 ^ C2) = C1 = f(F1 ^ C0) ==> F1 = P1 ^ C2 ^ C0
# f(P2 ^ C1) = C0 = f(F0 ^ IV) ==> F0 = P2 ^ C1 ^ IV

def xor(a, b):
    return bytes([i ^ j for i,j in zip(a, b)])

f0 = xor(xor(p2, c1), iv)
f1 = xor(xor(p1, c2), c0)
f2 = xor(xor(p0, iv), c1)
print(f0 + f1 + f2)
# b'blahaj{abstr4ct_ouT_th3_AESECB_n_it5_just_X0RRR}'