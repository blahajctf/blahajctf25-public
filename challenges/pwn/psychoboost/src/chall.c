#include <stdio.h>

int main(void) {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  printf("IT FEELS LIKE YOU A PART OF %p > ", stderr);
  fgets((char *) stderr, 0x300, stdin);
  return 0;
}
