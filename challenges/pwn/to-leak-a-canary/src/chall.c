// gcc -o chall chall.c -fstack-protector -no-pie
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void gift() {
    __asm__("pop %rsi; ret; pop %rdx; ret; pop %rdi; ret;");
}

void gift2(){
    __asm__("pop %rax; ret; syscall; ret;");
}



int main(){
    puts("This challenge will teach you some basics on printf() and canaries\n");
    char buf[100];
    printf("Sympath leak: %p\n",buf);
    for (int i=0;i<2;i++){
        int nbytes=read(0,buf,0x100);
        printf("%s\n",buf);
    }
    return 0;
}   
