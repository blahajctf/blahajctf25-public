# first you study the structure of chal, and realize that the signal handler we install will just jump over all the \x48\xa1\x69 bad instructions whenever we reach them. these instructions also break the decompile/disasm
# so we replace them with nops, and the decompiler is happy

f = open("chal", "rb")
r = f.read().replace(b"\x48\xa1\x69", b"\x90\x90\x90")
f = open("chal2", "wb")
f.write(r)
f.close()

# after this you can just decompile as per usual and solve