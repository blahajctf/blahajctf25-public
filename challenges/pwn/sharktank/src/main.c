#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

typedef struct Investment {
  char *stock_ticker;
  char investor[8];
  double revenues[64];
  double dividends[128];
} Investment;

typedef struct Account {
  double principal;
  double interest;
  bool deleted;
} Account;


int read_int(char *prompt) {
  printf("%s", prompt);
  char buf[32];
  fgets(buf, sizeof(buf), stdin);
  return atoi(buf);
}

double read_double(char *prompt) {
  printf("%s", prompt);
  char buf[32];
  char *end;
  fgets(buf, sizeof(buf), stdin); 
  return strtod(buf, &end);
}

void read_str(char *prompt, char *buf, ssize_t size) {
  printf("%s", prompt);
  fgets(buf, size, stdin);
  buf[strcspn(buf, "\n")] = '\0';
}

void view_investment(Investment* investment) {
  printf("INVESTMENT ACCOUNT %s\n----\nMAIN INVESTOR: %s\n", investment->stock_ticker, investment->investor);
}

void rename_ticker(Investment* investment) {
  printf("WHAT IS THE NAME OF OUR NEW TICKER? >");
  fgets(investment->stock_ticker, 8, stdin);
}

char menu(void) {
  puts("WELCOME TO SHARK TANK");
  puts("(1) CREATE NEW ACCOUNT");
  puts("(2) DELETE EXISTING ACCOUNT");
  puts("(3) INCREASE INTEREST RATE");
  puts("(4) RENAME STOCK TICKER");
  puts("(5) ACCRUE INTEREST");
  printf("WHAT IS YOUR CHOICE > ");
  char c = getc(stdin);
  getchar();
  return c;
}

int main(void){
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  Account* accounts[8] = {0};
  Investment* investment = malloc(sizeof(Investment));
  int idx;
  char c;
  investment->stock_ticker = "SHARKCO\0";
  strncpy(investment->investor, "IKEA", sizeof(investment->investor));
  int b=1;
  while (b) {
    switch (menu()) {
      case '1':
        idx = read_int("WHERE WOULD WE LIKE TO MAKE A NEW ACCOUNT? > ");
        
        if ((idx < 0) || (idx >= 8)) {
          printf("%d IS OUT OF BOUNDS.", idx);
          exit(0);
        }

        if (accounts[idx] && !accounts[idx]->deleted) {
          printf("AN ACCOUNT ALREADY EXISTS AT %d.", idx);
          exit(0);
        }

        accounts[idx] = malloc(sizeof(Account));
        accounts[idx]->deleted = false;
        puts("SUCCESSFULLY CREATED NEW ACCOUNT.");
        break;

      case '2':
        idx = read_int("WHICH ACCOUNT WOULD WE LIKE TO DELETE? > ");
    
        if (idx >= 8) {
          printf("%d IS OUT OF BOUNDS.", idx); 
          exit(0);
        }

        if (!accounts[idx]) {
          printf("NO ACCOUNT EXISTS AT %d.", idx);
          exit(0); 
        }
        
        if (accounts[idx]->deleted) {
          printf("THAT ACCOUNT IS ALREADY DELETED.");
          exit(0);
        }

        printf("ACCOUNT AT %d\n---\nPRINCIPAL: %.17g, INTEREST: %.17g\n", 
              idx, 
              accounts[idx]->principal,
              accounts[idx]->interest);

        printf("FREE IT? (Y/N) > ");
        c = getc(stdin);
        getchar();
        if (c == 'Y') {
          free(accounts[idx]);
          accounts[idx]->deleted = true;
          puts("ACCOUNT FREED.");
        }
        break;

      case '3':
        idx = read_int("WHICH ACCOUNT WOULD WE LIKE TO EDIT? > ");
        
        if ((idx < 0) || (idx >= 8)) {
          printf("%d IS OUT OF BOUNDS.\n", idx);
          exit(0);
        }

        if (!accounts[idx]) {
          printf("NO ACCOUNT EXISTS AT %d.\n", idx);
          exit(0);
        }

        if (accounts[idx]->deleted) {
          puts("THAT ACCOUNT IS ALREADY DELETED.");
          exit(0);
        }

        accounts[idx]->interest  = read_double("INTEREST > ");
        puts("SUCCESSFULLY SET NEW INTEREST.");
        break;

      case '4':
	printf("You can only do this one\n");
        rename_ticker(investment);
        b=0;
	break;
      case '5':
        for (int i = 0; i<8; i++) {
          if (accounts[i] && !accounts[i]->deleted) {
            accounts[i]->principal *= accounts[i]->interest; 
            printf("ACCOUNT AT %d NOW HAS $%.17g.\n", i, accounts[i]->principal);
          }
        }
        break;
    } 
  }
  puts(NULL);
}
