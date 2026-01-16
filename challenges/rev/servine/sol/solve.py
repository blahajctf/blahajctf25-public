import random

def solve():
    target_nums = [
        1454433542, 955021940, 2872705261, 1399142311, 
        2924800640, 3026681276, 1547421538, 933541538, 
        1051185089, 2694598254, 2712507769, 4180449996, 
        3943065784, 1268979863, 2359636600, 2675638245
    ]
    
    random.seed(b'servine')
    
    xor_keys = [random.getrandbits(32) for _ in range(16)]
    mult_keys = [random.getrandbits(32) for _ in range(9)]
    add_keys = [random.getrandbits(32) for _ in range(2, 14)] # Maps to indices 2-13
    
    indices = list(range(16))
    random.shuffle(indices)
    
    state = [0] * 16
    for i, original_pos in enumerate(indices):
        state[original_pos] = target_nums[i]

    MOD = 4294967296

    def solve_linear(a, b, m):
        import math
        g = math.gcd(a, m)
        if b % g != 0:
            return []
        a_p = a // g
        b_p = b // g
        m_p = m // g
        inv = pow(a_p, -1, m_p)
        x0 = (b_p * inv) % m_p
        
        return [x0 + k * m_p for k in range(g)]

    def ror(val, r_bits, max_bits=32):
        r_bits %= max_bits
        return ((val >> r_bits) | (val << (max_bits - r_bits))) & ((1 << max_bits) - 1)

    recovered_chunks = [None] * 16

    for i in range(16):
        val = state[i]
        
        if 2 <= i <= 13:
            k = add_keys[i - 2]
            val = (val - k) % MOD
            
        candidates = []
        if 0 <= i <= 8:
            k = mult_keys[i]
            sols1 = solve_linear(k, val, MOD)
            sols2 = solve_linear(k, val ^ 1, MOD) 
            candidates = sols1 + sols2
        else:
            candidates = [val]
            
        next_candidates = []
        if 5 <= i <= 15:
            for c in candidates:
                next_candidates.append(ror(c, i))
        else:
            next_candidates = candidates
        candidates = next_candidates
        
        k = xor_keys[i]
        final_candidates = [c ^ k for c in candidates]
        
        valid_chunk = None
        for fc in final_candidates:
            try:
                b = fc.to_bytes(4, 'big')
                if all(0x20 <= x <= 0x7E for x in b):
                    valid_chunk = b
                    break
            except OverflowError:
                continue
                
        if valid_chunk:
            recovered_chunks[i] = valid_chunk

    full_bytes = b''.join([c for c in recovered_chunks if c])
    attack = full_bytes.decode('utf-8').lstrip('0')
    print(attack)

if __name__ == '__main__':
    solve()
