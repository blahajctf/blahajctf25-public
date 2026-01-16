from pwn import *
from sympy import isprime
from Crypto.Util.number import bytes_to_long

p = remote('172.17.0.2', 1337)

target_msg = b"winner"
target_int = bytes_to_long(target_msg)

context.log_level = 'debug'

p.recvuntil(b'n = ')
n = int(p.recvline().decode()[:-1])

for i in range(2048, 0, -1):
    new_n = n ^ (1 << i)
    if isprime(new_n):
        print(f'found {i}')
        #
        p.sendline(str(i))
        d = pow(65537, -1, new_n-1)
        signature = pow(target_int, d, new_n)
        p.sendline(hex(signature))
        while True:
            print(p.recvline())
