Intended solve path: printf("%s",some_ptr) prints everything till it encounters a null byte and canaries LSB can be corrupted and it wont cause stack_chk_fail to occur. Hence, you can corrupt caanary's LSB to b'\n' and cause printf to leak canary. Since libc leak is given and AMPLE pop gadgets are given, you can do a ret2syscall to gain shell

Unintended solve paths: there shouldn't be any

Potential problems: Literally none
