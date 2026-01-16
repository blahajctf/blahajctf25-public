from Crypto.Cipher import AES 
import os

flag = b"blahaj{REDACTEDREDACTEDREDACTEDREDACTEDREDACTED}"
# assert len(flag) == 48

iv = os.urandom(16)
key = os.urandom(16)
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(flag)
c0, c1, c2 = ciphertext[:16], ciphertext[16:32], ciphertext[32:48]

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(c2 + c1 + c0)

print("IV         :", iv.hex())
print("PLAINTEXT  :", plaintext.hex())  # this isn't the flag... D:
print("CIPHERTEXT :", ciphertext.hex())
"""
IV         : a74286dc53a7e51a19de722b1e22a9bd
PLAINTEXT  : 03a4113b96b860e0fafd6a00c3583f1712c0ba08dd46547ddb87f3d61f838a323ea10466a8b86ef2ecd14642a5691935
CIPHERTEXT : 220c4c94a435fe05c4432802208cc612fb8fe3d29a75f089977c401b8f28c4d75fb9a2c30d1b99275e8188917c4d134e
"""