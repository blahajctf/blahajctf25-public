#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// gcc -g -O0 -o main main.c
// only the main() function has a bug!
// please only look at the main() function so you don't get overwhelmed.

#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define BOLD    "\033[1m"
#define RESET   "\033[0m"

void win(void) {
  system("cat flag.txt");
}

void init(void) {
  puts(BLUE BOLD "==================================================" RESET);
  puts(MAGENTA "// DISTURBING THE PEACE \\\\" RESET);
  puts(YELLOW "Watch out leader! This monster's strong..." RESET);
  puts("I'm not sure you'll be able to beat it with attacking alone!");
  puts(RED BOLD "// - SURPRISE ATTACK! - \\\\" RESET);
  puts(BLUE BOLD "==================================================" RESET);
  printf("\n");
}

void print_battle(int monster_hp, int player_hp) {
  puts(CYAN "--------------------------------------------------" RESET);
  printf(BOLD RED "ENEMY HP: %d\n" RESET, monster_hp);
  printf(BOLD GREEN "YOUR  HP: %d\n" RESET, player_hp);
  puts(CYAN "--------------------------------------------------" RESET);
}

void menu() {
  puts(BOLD YELLOW "\n================= ACTION MENU =================" RESET);
  printf(GREEN  "1 > MELEE ATTACK\n" RESET);
  printf(CYAN   "2 > SWAP PERSONAS\n" RESET);
  printf(RED    "3 > FLEE\n" RESET);
  puts(BOLD YELLOW "===============================================" RESET);
}

void flee() {
  printf(MAGENTA "Leader, you want to run away? Okay.. if that's your call!\n" RESET);
  exit(0);
}

void monster_attack(int *player_hp) {
  puts(RED BOLD "\n!! The monster lunges! It does 100 damage." RESET);
  puts(YELLOW "Leader, are you okay?" RESET);
  *player_hp = *player_hp - 100;
}


int main(void) {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  int monster_hp = 25000; 
  char persona[16];
  int player_hp = 500;

  init();
  
  while ((player_hp > 0) && (monster_hp > 0)) {
    print_battle(monster_hp, player_hp);
    menu();
    printf(BOLD "YOUR INPUT > " RESET);

    char c = getc(stdin);
    getchar(); // exhaust newline

    switch (c) {
       case '1': {
        puts(GREEN "MELEE ATTACK! You did 50 damage to the monster." RESET);
        monster_hp -= 50;
        break;
      }

      case '2': {
        printf(CYAN "What persona are you going to switch to, leader? > " RESET);
        fgets(persona, 32, stdin);
        break;  
      }

      case '3': {
        flee();
        break;
      }

      default:
        puts(RED "Invalid option, leader!" RESET);
    }

    monster_attack(&player_hp);
  }

  if (player_hp <= 0) {
    puts(RED "\nYour eyes are getting weary..." RESET);
    puts(YELLOW "Better luck next time!" RESET);
    exit(0);
  }

  if (monster_hp <= 0) {
    puts(GREEN BOLD "\nYou've defeated the monster! Good job, leader!" RESET);
    win();
    exit(0);
  }
}

