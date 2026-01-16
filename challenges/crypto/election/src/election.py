import sys
from Crypto.PublicKey import DSA
from Crypto.Hash import TupleHash128
from Crypto.Random.random import randrange

KEY_SIZE = 2048
Q_BITS = 256
HASH_BITS = 128

# Our election implementation follows https://berry.win.tue.nl/papers/euro97.pdf

def init_params():
    """Initializes the ElGamal public parameters using DSA standards."""
    key = DSA.generate(KEY_SIZE)
    params = {
        'p': key.p,  
        'q': key.q,  
        'g': key.g,  
        'y': key.y   
    }
    
    return params, key.x

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
        a = randrange(1, q)
        c1 = randrange(1, 2**HASH_BITS)
        f1 = randrange(1, q)

        A0 = pow(g, a, p)
        B0 = pow(y, a, p)
        A1 = (pow(g, f1, p) * pow(R_val, -c1, p)) % p
        s_div_g = (S_val * pow(g, -1, p)) % p
        B1 = (pow(y, f1, p) * pow(s_div_g, -c1, p)) % p
    
    elif choice == 1:
        a = randrange(1, q)
        c0 = randrange(1, 2**HASH_BITS)
        f0 = randrange(1, q)

        A1 = pow(g, a, p)
        B1 = pow(y, a, p)
        A0 = (pow(g, f0, p) * pow(R_val, -c0, p)) % p
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

    A0 = (pow(g, f0, p) * pow(R_val, -c0, p)) % p
    B0 = (pow(y, f0, p) * pow(S_val, -c0, p)) % p
    A1 = (pow(g, f1, p) * pow(R_val, -c1, p)) % p
    s_div_g = (S_val * pow(g, -1, p)) % p
    B1 = (pow(y, f1, p) * pow(s_div_g, -c1, p)) % p

    # Recompute the challenge hash
    challenge_hash = TupleHash128.new(digest_bytes=HASH_BITS // 8)
    for item in [A0, B0, A1, B1]:
        challenge_hash.update(item.to_bytes(KEY_SIZE // 8, 'big'))
        
    challenge = int.from_bytes(challenge_hash.digest(), 'big')

    # Check if the challenges sum up correctly
    return (c0 + c1) % (2**HASH_BITS) == challenge

def unseal_votes(params, private_key, final_vote, total_voters):
    """Unseals the final aggregated vote to reveal the number of votes for Candidate 1"""
    p, g = params['p'], params['g']
    R_final, S_final = final_vote
    
    R_final_inv_x = pow(R_final, -private_key, p)
    g_m = (S_final * R_final_inv_x) % p
    
    # To save on computation time, we only check up to the 50% threshold. 
    # Anything below that and Candidate 0 wins, else Candidate 1 wins
    winner = 1
    for m in range(total_voters//2):
        if pow(g, m, p) == g_m:
            winner = 0
    
    return winner

def main():
    
    print("=========================================")
    print("|                                       |")
    print("|             The BlahajCTF             |")
    print("|           Presidential Race           |")
    print("|                 2025                  |")
    print("|                                       |")
    print("=========================================")
    print()
    
    print("[ Voting Parameters ]")
    public_params, private_key = init_params()
    p = public_params['p']
    print("p =", hex(public_params['p']))
    print("q =", hex(public_params['q']))
    print("g =", hex(public_params['g']))
    print("y =", hex(public_params['y']))
    print("=========================================")
    print()
    
    total_voters = 100
    aggregated_R, aggregated_S = 1, 1
    
    # Candidate 1 is losing!
    for voter in range(total_voters-1):
        if voter < 10:
            # Candidate 1 gets only 10 votes :(
            vote, r = create_vote(public_params, 1) 
            proof = generate_proof(public_params, vote, r, 1)
        else:
            # Candidate 0 is leading this election...
            vote, r = create_vote(public_params, 0) 
            proof = generate_proof(public_params, vote, r, 0)
        
        if not verify_vote(public_params, vote, proof): 
            print("Spoiled ballot caught!")
            
        # Homomorphically combine the votes
        aggregated_R = (aggregated_R * vote[0]) % p
        aggregated_S = (aggregated_S * vote[1]) % p
    
    print("[ Votes Cast: 99 ]")
    print()
    print("Now cast your vote!")
    
    # create a vote and proof using create_vote and generate_proof
    try:
        R   = int(input("R: "), 16)
        S   = int(input("S: "), 16)
        c0  = int(input("c0: "), 16)
        c1  = int(input("c1: "), 16)
        f0  = int(input("f0: "), 16)
        f1  = int(input("f1: "), 16)
    except EOFError:
        exit(0)
    
    user_vote = (R, S)
    user_proof = (c0, c1, f0, f1)
    
    if not verify_vote(public_params, user_vote, user_proof): 
        print()
        print("Spoiled ballot caught! Nice try...")
    else:
        print()
        print("Your ballot has been counted!")
        aggregated_R = (aggregated_R * R) % p
        aggregated_S = (aggregated_S * S) % p

    winner = unseal_votes(public_params, private_key, (aggregated_R, aggregated_S), total_voters)

    print("=========================================")
    print("Winner:", winner)
    if winner == 0:
        print("Candidate 0 wins the election! Boohoo...")
    elif winner == 1:
        print("Candidate 1 wins the election! How?!?!")
        print()
        f = open("flag.txt", "r")
        flag = f.read()
        f.close()
        print("Flag:", flag)

if __name__ == "__main__":
    main()