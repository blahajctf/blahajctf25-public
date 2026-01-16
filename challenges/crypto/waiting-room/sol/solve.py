from pwn import *
import hlextend
import base64

context.log_level = 'DEBUG'

# p = process(['python', 'waiting_room.py'])
p = remote('127.0.0.1', 1337)
p.sendlineafter(b'>', b'1')
p.sendlineafter(b'>', b'blahaj')
p.sendlineafter(b'>', b'4')

p.recvuntil(b'IDENTIFICATION.\n')

exec(p.recvline().decode())
exec(p.recvline().decode())

message = base64.b64decode(message)
print(hash)

sha = hlextend.new('sha256')
msg = sha.extend(b';queue_number=1', message, 64, hash)

p.sendlineafter(b'>', b'2')
p.sendlineafter(b'>', base64.b64encode(msg))
p.sendlineafter(b'>', sha.hexdigest().encode())
p.sendlineafter(b'>', b'3')
p.interactive()
