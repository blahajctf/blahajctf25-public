from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
import os

def encrypt(k, iv, pt):
    cipher = AES.new(k, AES.MODE_CTR, nonce=iv)
    return cipher.encrypt(pad(pt, 16))

def decrypt(k, iv, ct):
    cipher = AES.new(k, AES.MODE_CTR, nonce=iv)
    return unpad(cipher.decrypt(ct), 16)

def main():
    try:
        iv = os.urandom(8)
        key = os.urandom(16)
        
        msg = input("Your input plaintext: ")
        print("Encrypted flag (hex):", encrypt(key, iv, b"blahaj{n30N_93N3515_3nCrYP710n_5y573M}").hex())
        print("Encrypted input (hex):", encrypt(key, iv, msg.encode()).hex())
        print()
    except EOFError:
        exit(0)
    except:
        print("Please input a valid number!")

if __name__ == "__main__":
    main()