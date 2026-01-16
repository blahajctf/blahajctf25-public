import sys
from Crypto.PublicKey import DSA
from Crypto.Hash import TupleHash128
from Crypto.Random.random import randrange

KEY_SIZE = 2048
Q_BITS = 256
HASH_BITS = 128

def create_vote(params, choice):
    """Creates an ElGamal ciphertext for a given choice (0 or 1)."""
    p, q, g, y = params['p'], params['q'], params['g'], params['y']

    r = randrange(1, q)
    R = pow(g, r, p)
    S = (pow(y, r, p) * pow(g, choice, p)) % p

    return (R, S), r

def generate_proof(params, vote, r, choice):
    """Generates a Chaum-Pederson proof that the vote is for 0 OR 1."""
    p, q, g, y = params['p'], params['q'], params['g'], params['y']
    R_val, S_val = vote

    # The prover must prove knowledge of r for one of two statements:
    # Statement 0: log_g(R) = log_y(S)  (vote is 0)
    # Statement 1: log_g(R) = log_y(S/g) (vote is 1)

    if choice == 0:
        # Real proof for choice 0, simulated for choice 1
        a = randrange(1, q)
        c1 = randrange(1, 2**HASH_BITS)
        f1 = randrange(1, q)

        A0 = pow(g, a, p)
        B0 = pow(y, a, p)
        
        # Simulating the other branch of the proof
        # A1 = g^f1 * R^(-c1)
        A1 = (pow(g, f1, p) * pow(R_val, -c1, p)) % p
        # B1 = y^f1 * (S/g)^(-c1)
        s_div_g = (S_val * pow(g, -1, p)) % p
        B1 = (pow(y, f1, p) * pow(s_div_g, -c1, p)) % p
    
    elif choice == 1:
        # Real proof for choice 1, simulated for choice 0
        a = randrange(1, q)
        c0 = randrange(1, 2**HASH_BITS)
        f0 = randrange(1, q)

        A1 = pow(g, a, p)
        B1 = pow(y, a, p)
        
        # Simulating the other branch of the proof
        # A0 = g^f0 * R^(-c0)
        A0 = (pow(g, f0, p) * pow(R_val, -c0, p)) % p
        # B0 = y^f0 * S^(-c0)
        B0 = (pow(y, f0, p) * pow(S_val, -c0, p)) % p

    challenge_hash = TupleHash128.new(digest_bytes=HASH_BITS // 8)
    for item in [A0, B0, A1, B1]:
        challenge_hash.update(item.to_bytes(KEY_SIZE // 8, 'big'))
    
    challenge = int.from_bytes(challenge_hash.digest(), 'big')

    if choice == 0:
        c0 = (challenge - c1) % (2**HASH_BITS)
        f0 = (a + c0 * r) % q
    else: 
        c1 = (challenge - c0) % (2**HASH_BITS)
        f1 = (a + c1 * r) % q

    return (c0, c1, f0, f1)

def verify_vote(params, vote, proof):
    """Verifies a Chaum-Pederson proof."""
    p, g, y = params['p'], params['g'], params['y']
    R_val, S_val = vote
    c0, c1, f0, f1 = proof

    # Recompute A0, B0, A1, B1 from the proof
    # A0 = g^f0 * R^(-c0)
    A0 = (pow(g, f0, p) * pow(R_val, -c0, p)) % p
    # B0 = y^f0 * S^(-c0)
    B0 = (pow(y, f0, p) * pow(S_val, -c0, p)) % p
    
    # A1 = g^f1 * R^(-c1)
    A1 = (pow(g, f1, p) * pow(R_val, -c1, p)) % p
    # B1 = y^f1 * (S/g)^(-c1)
    s_div_g = (S_val * pow(g, -1, p)) % p
    B1 = (pow(y, f1, p) * pow(s_div_g, -c1, p)) % p

    # Recompute the challenge hash
    challenge_hash = TupleHash128.new(digest_bytes=HASH_BITS // 8)
    for item in [A0, B0, A1, B1]:
        challenge_hash.update(item.to_bytes(KEY_SIZE // 8, 'big'))
        
    challenge = int.from_bytes(challenge_hash.digest(), 'big')

    # Check if the challenges sum up correctly
    return (c0 + c1) % (2**HASH_BITS) == challenge

def create_spoiled_vote(params):
    p, q, g, y = params['p'], params['q'], params['g'], params['y']
    
    while True:
        s = randrange(1, q)
        t = randrange(1, q)
        f0 = randrange(1, q)
        c0 = 0 

        A0 = pow(g, f0, p)
        B0 = pow(y, f0, p)
        A1 = pow(g, s, p)
        B1 = pow(y, t, p)
        
        challenge_hash = TupleHash128.new(digest_bytes=HASH_BITS // 8)
        for item in [A0, B0, A1, B1]:
            challenge_hash.update(item.to_bytes(KEY_SIZE // 8, 'big'))
        
        challenge = int.from_bytes(challenge_hash.digest(), 'big')
        c1 = challenge

        try:
            inv_c1 = pow(c1, -1, q)
            inv_1_minus_c1 = pow(1 - c1, -1, q)
            break 
        except ValueError:
            continue
    
    
    f1 = (s * inv_1_minus_c1) % q
    R = pow(g, f1, p)
    
    term1 = pow(g, c1, p)
    term2 = pow(y, (f1 - t) % q, p)
    S = pow((term1 * term2) % p, inv_c1, p)
    
    proof = (c0, c1, f0, f1)
    vote = (R, S) # our vote encodes some random number but that's like sixteen quadrillion fake votes for Candidate 1
    
    # We can assert that the generated vote and proof are valid
    assert verify_vote(params, vote, proof), "Verification of spoiled vote failed!"
    
    return vote, proof

def main():
    
    public_params = {}
    # put your params here
    p = 0x0
    q = 0x0
    g = 0x0
    y = 0x0
    public_params['p'] = p
    public_params['q'] = q
    public_params['g'] = g
    public_params['y'] = y
    
    vote, r = create_vote(public_params, 1) 
    proof = generate_proof(public_params, vote, r, 1)
    print("R = ", hex(vote[0]))
    print("S = ", hex(vote[1]))
    print("c0 = ", hex(proof[0]))
    print("c1 = ", hex(proof[1]))
    print("f0 = ", hex(proof[2]))
    print("f1 = ", hex(proof[3]))
    
    spoiled_vote, spoiled_proof = create_spoiled_vote(public_params)
    print("==== SPOILED ====")
    print("R = ", hex(spoiled_vote[0]))
    print("S = ", hex(spoiled_vote[1]))
    print("c0 = ", hex(spoiled_proof[0]))
    print("c1 = ", hex(spoiled_proof[1]))
    print("f0 = ", hex(spoiled_proof[2]))
    print("f1 = ", hex(spoiled_proof[3]))


if __name__ == "__main__":
    main()