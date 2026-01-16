#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct {
  char name[8];
  char favorite_ice_cream[16];
} Member;


void win(void) {
  puts("wow! you've proven yourself as a true fan!\nhere's your flag: [redacted]");
  exit(0);
}

void menu(void) {
  puts("1. read a member's information");
  puts("2. edit a member's information");
  puts("---");
  printf("select an option > ");
}

void print_member(Member member) {
  printf("---\n%s's favorite ice cream flavor is %s!\n", member.name, member.favorite_ice_cream);
}

int main(void) {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  puts("welcome to the le sserafim fansite!");
  printf("my deepest kpop secret is at %p...\n", win);
  puts("---");
  Member members[] = {
    {"chaewon", "mint"},
    {"eunchae",  "choco"},
    {"yunjin",  "vanilla"},
    {"sakura",  "cherry"},
    {"kazuha",  "apple"},
  };
  while (true) {
    menu();
    char c = getc(stdin);
    char inp[16] = "\0";
    getchar();
    switch (c) {
      case '1':
        printf("who would you like to look up? > ");
        fgets(inp, sizeof(inp), stdin);
        print_member(members[atoi(inp)]);
        break;
      case '2':
        printf("whose favorite ice cream would you like to edit? > ");
        fgets(inp, sizeof(inp), stdin);
        printf("what would you like to edit it to? > ");
        fgets(members[atoi(inp)].favorite_ice_cream, 16, stdin); 
        break;
      default:
        puts("see you another time!");
        return 0;
    }
  }
}
