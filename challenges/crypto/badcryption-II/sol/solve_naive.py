# solve script for badcryption (pohlig hellman attack)
from sympy import primefactors, mod_inverse
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import time

def decrypt_to_plaintext(ciphertext_b64, iv_hex, key):
    # parse from string hex value to bytes
    try: 
        ciphertext = base64.b64decode(ciphertext_b64)
        iv = bytes.fromhex(iv_hex)
        key = hashlib.sha256(str(key).encode()).digest()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
        print("Decrypted plaintext:", plaintext.decode())
    except:
        pass

def brute_force_privatekey(prime, generator, public_key):
    start = time.time()
    for private_key in range(1, prime):
        if private_key % 1000000 == 0:
            print("Trying private key:", private_key)
            print("Elapsed time:", time.time() - start)
        if pow(generator, private_key, prime) == public_key:
            return private_key
    return None

private_key = brute_force_privatekey(59222853856902777191163312203, 5, 58676250442558202826756830271)
print("Found private key:", private_key)

shared_key = pow(82237, private_key, 59222853856902777191163312203)
print("Computed shared key:", shared_key)

decrypt_to_plaintext('FVCQO23lq+e1t2dxFNgQhnaqa+OLMCaifJyujLi922g=', '612edf1325b7cf4afe378ba7c8560b4b', shared_key)
