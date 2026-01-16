## Badcryption writeup
This is a pohlig hellman subgroup attack.

Notice how the prime given (49278241238643848738524823448834114960140393694771426989126687) 
can have its order (-1 from the original prime) factorised into small primes like [15619, 2, 17419, 29671, 39323, 53327, 69193...]

We find generators for these subgroups by applying g (5 in this case) ^ (large prime order/small prime order) (g1) and do the same to project the known public prime into these subgroups. (h1)

We brute force private keys for each of these primes given the group (g1, h1, p) finding g1 ^ k mod the original large prime p.

Once the "k" is found for this smaller discrete logarithm problem, we know that k is equal to private key mod (order of subprime)

Next, using chinese remainder theorem we can compute the original private key by finding a number that satisfys all the mod equations and decrypt by hashing that answer, then using it to decrypt AES (given in html)
