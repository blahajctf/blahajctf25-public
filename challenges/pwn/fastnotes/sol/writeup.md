Intended solve path: Create 2 >0x400 fake chunks by manipulating fastbin and tcache (basically a convoluted house of spirit), free to unsorted to get libc leak, largebin attack to overwrite file struct pointer to chunk address, fsop

Potential unintended solve paths: While the first part of the exploit most likely is the same to gain libc leak since fastbin consolidation to gain libc_leak cant work here since you cant create any more chunks after u malloc a special (>0x400) chunk, perhaps the largebin attack can be entirely avoided somehow?

Potential issues: Player did not use patched binary to run their exploit against 
                  
