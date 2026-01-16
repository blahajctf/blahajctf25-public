#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

char *chunk_addrs[0x10] = {0};
int idx = 0;
void leave(char *msg)
{
    puts(msg);
    return;
}
void *goodbye = &leave;
char *goodbye_msg = "'What time is it' is a key question of the underground movement. Studying the texts is essential\n";
char *entry_msg = "Did you watch one battle after another?\n";
char *ash = "a"; // ignore this.

void wrapUp()
{
    ((void (*)(char *))goodbye)(goodbye_msg);
    return;
}

int main()
{
    puts(entry_msg);
    int opt = 0;
    int d = 1;
    while (d)
    {
        printf("What time is it?\n");
        printf("[1] Come up with an answer\n");
        printf("[2] Modify your answer\n");
        printf("[3] Forget your answer\n");
        printf("[4] Remember your answer\n");
        printf("[5] Just give up\n");
        scanf("%d", &opt);
        getchar();
        switch (opt)
        {
        case 1:
            if (idx == 0x10)
            {
                printf("Too many answers\n");
                _exit(0);
            }
            printf("How long is your answer? Let's keep it below 0x40 words\n");
            unsigned int size = 0;
            scanf("%d", &size);
            getchar();
            if (size > 0x40)
            {
                printf("hell nah\n");
                _exit(0);
            }
            char *ans = malloc(size);
            chunk_addrs[idx] = ans;
            printf("What's your answer?\n");
            fgets(ans, size, stdin);
            idx++;
            break;
        case 2:
            printf("Where was your answer stored\n");
            unsigned int idx_of_ans = 0;
            scanf("%d", &idx_of_ans);
            getchar();
            if (idx_of_ans >= 0x10 || chunk_addrs[idx_of_ans] == 0)
            {
                printf("EH EH EH! that's not allowed\n");
                _exit(0);
            }
            printf("Tell me. What do you want to change your answer to? Note: I won't let you change your answer fully so make this count\n");
            read(0, (char *)(chunk_addrs[idx_of_ans]), 0x8);
            break;
        case 3:
            printf("Which answer would you like to forget?\n");
            unsigned int idx_of_ans_to_delete = 0;
            scanf("%d", &idx_of_ans_to_delete);
            getchar();

            if (idx_of_ans_to_delete >= 0x10 || chunk_addrs[idx_of_ans_to_delete] == 0)
            {
                printf("EH EH EH! that's not allowed\n");
                _exit(0);
            }
            free(chunk_addrs[idx_of_ans_to_delete]);
            break;
        case 4:
            printf("Which answer would you like to remember?\n");
            unsigned int idx_of_ans_to_remember = 0;
            scanf("%d", &idx_of_ans_to_remember);
            getchar();

            if (idx_of_ans_to_remember >= 0x10 || chunk_addrs[idx_of_ans_to_remember] == 0)
            {
                printf("EH EH EH! that's not allowed\n");
                _exit(0);
            }
            puts(chunk_addrs[idx_of_ans_to_remember]);
            break;
        case 5:
            printf("Wrong answer...\n");
            d--;
            break;
        default:
            d++;
            break;
        }
        if (d == 2)
        {
            break;
        }
    }
    if (d == 0)
    {
        wrapUp();
    }
    if (d == 2)
    {
        leave(goodbye_msg);
    }
    return 0;
}