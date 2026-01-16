Intended solve path: Ret2dlresolve 2x to overwrite fprintf with mprotect and seccomp_release with any function (i did it with puts()), set up your payload correctly such that mprotect(bss,0x1000,0x7) is called, in cleanUp(), write shellcode to call process_vm_readv to read memory within address space of the test process to then write it out to stdout to leak flag.

Maybe Unintended solve path: Maybe you can leak libc and avoid doing ret2dlresolve or my seccomp filter had a gap to allow unintended syscalls

