#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    FILE *f = fopen("in_utero.txt", "r");
    char buf[100000];
    int c;
    int i = 0;
    while ((c = fgetc(f)) != EOF) {
        putchar(c);
        if (c == '\n') buf[i] = '\0';
        else buf[i] = c;
        i++;
    }
    
    fclose(f);
    FILE *flag = fopen("flag.txt", "r");
    
    i = 1024;
    while ((c = fgetc(flag)) != EOF) {
        buf[i] = c;
        i++;
    }
    
    char input[2048];
    printf("\n\nHEY! WAIT! I GOT A REAL COMPLAINT: > ");
    fgets(input, sizeof(input) - 1, stdin);
    printf(input);
    return 0;
}
