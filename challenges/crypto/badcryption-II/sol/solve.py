# solve script for badcryption (pohlig hellman attack)
from sympy import primefactors, mod_inverse
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import time

generator = 5
prime = 49278241238643848738524823448834114960140393694771426989126687
known_public = 10800503958313532508703483527316858486221753413274690920762040
received_public = 1408737133570836687938369313016555892179945972238420904039351

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


def find_prime_factors(j):
    factors = []
    n = 2
    # Brute Force Primes
    while n <= j:
        if j % n == 0:
            # Found factor
            factors += [n]
            j //= n
        else:
            n += 1
    return factors

def project_into_subgroup(element, prime, subgroup_order):
    exponent = (prime - 1) // subgroup_order # exponent to project is order of full group / order of subgroup
    new_generator = pow(generator, exponent, prime)
    return new_generator, pow(element, exponent, prime) # second is proejcted value
    # equal to g1, h1

def brute_force_privatekey(prime, generator, public_key, modulo):
    start = time.time()
    for private_key in range(1, prime):
        if pow(generator, private_key, modulo) == public_key:
            return private_key
    return None

start = time.time()
# Step 1: Find prime factors of p-1
factors = find_prime_factors(prime - 1)
print("Prime factors of p-1:", factors)

# Step 2: For each prime factor, project
subgroup_elements = []
for q in factors:
    g1, h1 = project_into_subgroup(known_public, prime, q)
    subgroup_elements.append((q, g1, h1))
    print(f"Subgroup of order {q}: generator {g1}, public {h1}")

# Step 3: Brute force each subgroup to find private key mod q
private_key_mods = []
for (q, g1, h1) in subgroup_elements:
    print(f"Brute forcing subgroup of order {q}...")
    dlog = brute_force_privatekey(q, g1, h1, prime)
    print(f"Found private key mod {q}: {dlog}") # dlog is private key mod q
    private_key_mods.append((dlog, q))

# Step 4: Combine using CRT

from sympy.ntheory.modular import crt
rems = [rems for (rems, mods) in private_key_mods]
mods = [mods for (rems, mods) in private_key_mods]
private_key, _ = crt(mods, rems)
print("Combined private key:", private_key)

# Step 5: Compute shared key 
shared_key = pow(received_public, private_key, prime)
print("Computed shared key:", shared_key)

# Step 6: Decrypt message


decrypt_to_plaintext('oDdTRGeG7vChufQ1k9vK7CSDhcTASt0z0QIoprH04Kw=', '27899e4a13288b70c146368509f07b03', shared_key)

print("Time elapsed: ", time.time() - start)
