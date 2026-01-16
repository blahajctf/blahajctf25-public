// gcc -o fastnotes fastnotes.c -fstack-protector -fPIE -z relro -z now
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/prctl.h>
#include <asm/unistd.h>
#include <stddef.h>
#include <stdbool.h>

#ifndef BPF_STMT
#define BPF_STMT(code, k) {(unsigned short)(code), 0, 0, k}
#endif
#ifndef BPF_JUMP
#define BPF_JUMP(code, k, jt, jf) {(unsigned short)(code), jt, jf, k}
#endif

void menu();
void createNote();
void viewNote();
void editNote();
void deleteNote();
void createSpecialNote();
void leave();
void correctInput(char *note, ssize_t len);
void somethingSpecial();

#define MAX_NOTES 8
#define SZ_SPECIAL_NOTES 0x500
int isCalled = 0;

char *chunk_ptrs[0x10] = {0};
int size_ptrs[0x10] = {0};
char *special_chunk_ptrs[2] = {0};
void **ptr_to_fp_chunk = NULL;
int idx = -1;
FILE *fp = NULL;
/** NOTE to players: ignore this function since remote binary does not involve this
 * However, if you're up for the challenge, recompile this binary with the function enabled
 * after uncommenting out this function and the region in main() and try it out ;)
int install_filter_via_prctl(void)
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
    {
        perror("prctl(NO_NEW_PRIVS)");
        return -1;
    }

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1)
    {
        perror("prctl(SECCOMP)");
        return -1;
    }
    return 0;
}
**/
void setup()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    /**
    if (install_filter_via_prctl() != 0)
    {
        fprintf(stderr, "failed to install filter\\n");
        return;
    }
        **/
}

int main()
{
    setup();
    char greeting[] = "Welcome to the FAST notes taking app\n";
    write(1, greeting, strlen(greeting));
    somethingSpecial();
    menu();
}

void menu()
{
    int opt = 0;
    char menuScreen[] = "Choose what you want to do\n1: Create a note\n2: Edit a note\n3: View a note\n4: Delete a note\n5: Create Special Notes\n";
    while (true)
    {
        write(1, menuScreen, strlen(menuScreen));
        scanf("%d", &opt);
        switch (opt)
        {
        case 1:
            createNote();
            break;
        case 2:
            editNote();
            break;
        case 3:
            viewNote();
            break;
        case 4:
            deleteNote();
            break;
        case 5:
            createSpecialNote();
            break;
        default:
            leave();
        }
    }
}
void cleanUp()
{
    char msg[] = "byebye";
    fwrite(msg, sizeof(char), 6, ptr_to_fp_chunk[0]);
    _exit(0);
}
void leave()
{
    uint idx = 0;
    write(1, "Hm...are you sure? Why not you edit 1 more note?\n", 50);
    for (int i = 0; i < 1; i++)
    {
        scanf("%d", &idx);
        int c;
        while ((c = getchar()) != '\n' && c != EOF)
            ;
        if (idx < MAX_NOTES)
        {
            /**the following lines were added to preserve my sanity */
            ssize_t len = read(0, ((char *)chunk_ptrs[idx] - 0x10), *(size_t *)((char *)chunk_ptrs[idx] - sizeof(size_t)));
            correctInput(chunk_ptrs[idx], len);
        }
    }
    cleanUp();
}

void correctInput(char *note, ssize_t len)
{
    if (len > 0 && note[len - 1] == '\n')
    {
        note[len - 1] = '\0';
    }
    else
    {
        note[len] = '\0';
    }
}

void createNote()
{
    if (idx >= MAX_NOTES || isCalled)
    {
        write(1, "NO MORE!\n", 9);
        return;
    }
    uint size = 0;
    scanf("%d", &size);
    if (size != 0 && size <= 0x80)
    {
        char *note = calloc(size, sizeof(char));
        ssize_t len = read(0, note, size - 1);
        correctInput(note, len);
        if (!strstr(note, "FAST:") || size > 0x60)
        {
            write(1, "Disgusting\n", 11);
            free(note);
        }
        else
        {
            idx++;
            chunk_ptrs[idx] = note;
            size_ptrs[idx] = size;
        }
    }
    return;
}

void editNote()
{
    uint idx = 0;
    scanf("%d", &idx);
    if (idx <= 0x10 && chunk_ptrs[idx] != 0)
    {
        ssize_t len = read(0, chunk_ptrs[idx], size_ptrs[idx] - 1);
        correctInput(chunk_ptrs[idx], size_ptrs[idx]);
    }
    return;
}

void viewNote()
{
    uint idx = 0;
    scanf("%d", &idx);
    if (idx <= 0x10 && chunk_ptrs[idx] != 0)
    {
        char *note = chunk_ptrs[idx];
        size_t len = 0;
        while (note[len] != '\0')
        {
            len++;
        }
        write(1, note, len);
    }
}

void deleteNote()
{
    uint idx = 0;
    scanf("%d", &idx);
    if (chunk_ptrs[idx] != 0)
    {
        free(chunk_ptrs[idx]);
    }
    return;
}

void somethingSpecial()
{
    fp = fopen("/tmp/specialNotes.txt", "w+"); // not the flag in case you where wondering
    ptr_to_fp_chunk = malloc(0x10);
    *ptr_to_fp_chunk = (char *)fp;
    fp = NULL;
}

void createSpecialNote()
{
    if (isCalled >= 2)
    {
        return;
    } // you can't run this function > 2 times
    int c;
    while ((c = getchar()) != '\n' && c != EOF)
        ;
    char *specialNote = malloc(SZ_SPECIAL_NOTES);
    ssize_t len = read(0, specialNote, SZ_SPECIAL_NOTES - 1);
    correctInput(specialNote, len);
    special_chunk_ptrs[++idx] = specialNote;
    isCalled++;
    return;
}
