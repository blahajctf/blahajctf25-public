## Solution writeup for keygen II

For this challenge, you only need to do arbituary encryption
(you DO NOT need to decrypt)

This is also possible via the standard AES oracle attack.

1. We take a portion of the servers ciphertext and decrypt to find the intermediate with AES POA
2. We take that random intermediate I, and xor the previous block with I xor PT 
(As such, when server decrypts I it has to xor with previous block, resulting in I xor I xor PT = PT)
3. We take the previous block, I xor PT, and set that as the new ciphertext
attaching a blank IV onto it and sending it to the server.
4. The server attempts to "decrypt" it and by repeating POA, we find the 
intermediate for the block (I xor PT)
5. We repeat this by doing step 2 again on this block and work backwards until encryption is complete.
