/*
https://github.com/mjosaarinen/tiny_sha3
*/
#include <stdio.h>
#include <cstdlib>  
#include <stddef.h>
#include <stdint.h>

#ifndef scary_num
#define scary_num 24
#endif

#ifndef ROTL64
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))
#endif

typedef struct {
    union {                                 // state:
        uint8_t b[200];                     // 8-bit bytes
        uint64_t q[25];                     // 64-bit words
    } st;
    int pt, rsiz, mdlen;                    // these don't overflow
} scary_structure;

void scary_0(uint64_t st[25])
{
    // constants
    const uint64_t keccakf_rndc[24] = {
        0x663754824001, 0x8175278208082, 0x84809558808a,
        0x813642181548688, 0x713982322808b, 0x4522018968001,
        0x899298282738081, 0x88398561408009, 0x548349414898a,
        0x8449625470088, 0x81413985498009, 0x79302827500a,
        0x5079818986808b, 0x869848624008b, 0x8472344058089,
        0x88657578003, 0x89617757918002, 0x8579621817080,
        0x329943412800a, 0x8527019839300a, 0x886959286958081,
        0x8311417768080, 0x2225718844001, 0x881252382098008
    };
    const int keccakf_rotc[24] = {
        1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
        27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };
    const int keccakf_piln[24] = {
        10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    };
    // variables
    int i, j, r;
    uint64_t t, bc[5];

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    uint8_t *v;

    // endianess conversion. this is redundant on little-endian targets
    for (i = 0; i < 25; i++) {
        v = (uint8_t *) &st[i];
        st[i] = ((uint64_t) v[0])     | (((uint64_t) v[1]) << 8) |
            (((uint64_t) v[2]) << 16) | (((uint64_t) v[3]) << 24) |
            (((uint64_t) v[4]) << 32) | (((uint64_t) v[5]) << 40) |
            (((uint64_t) v[6]) << 48) | (((uint64_t) v[7]) << 56);
    }
#endif

    // actual iteration
    for (r = 0; r < scary_num; r++) {
        // Theta
        for (i = 0; i < 5; i++) {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }

        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5) {
                st[j + i] ^= t;
            }
        }

        // Rho Pi
        t = st[1];
        for (i = 0; i < 24; i++) {
            j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = ROTL64(t, keccakf_rotc[i]);
            t = bc[0];
        }

        //  Chi
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++) {
                bc[i] = st[j + i];
            }
            for (i = 0; i < 5; i++) {
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }

        //  Iota
        st[0] ^= keccakf_rndc[r];
    }

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    // endianess conversion. this is redundant on little-endian targets
    for (i = 0; i < 25; i++) {
        v = (uint8_t *) &st[i];
        t = st[i];
        v[0] = t & 0xFF;
        v[1] = (t >> 8) & 0xFF;
        v[2] = (t >> 16) & 0xFF;
        v[3] = (t >> 24) & 0xFF;
        v[4] = (t >> 32) & 0xFF;
        v[5] = (t >> 40) & 0xFF;
        v[6] = (t >> 48) & 0xFF;
        v[7] = (t >> 56) & 0xFF;
    }
#endif
}

int scary_1(scary_structure *c, int mdlen)
{
    int i;
    for (i = 0; i < 25; i++) {
        c->st.q[i] = 0;
    }
    c->mdlen = mdlen;
    c->rsiz = 200 - 2 * mdlen;
    c->pt = 0;
    return 1;
}

int scary_2(scary_structure *c, const void *data, size_t len)
{
    size_t i;
    int j;
    j = c->pt;
    for (i = 0; i < len; i++) {
        c->st.b[j++] ^= ((const uint8_t *) data)[i];
        if (j >= c->rsiz) {
            scary_0(c->st.q);
            j = 0;
        }
    }
    c->pt = j;
    return 1;
}

void scary_3(scary_structure *c)
{
    c->st.b[c->pt] ^= 0x1F;
    c->st.b[c->rsiz - 1] ^= 0x80;
    scary_0(c->st.q);
    c->pt = 0;
}

void scary_4(scary_structure *c, void *out, size_t len)
{
    size_t i;
    int j;
    j = c->pt;
    for (i = 0; i < len; i++) {
        if (j >= c->rsiz) {
            scary_0(c->st.q);
            j = 0;
        }
        ((uint8_t *) out)[i] = c->st.b[j++];
    }
    c->pt = j;
}

int main() {
    char key[31] = {98, 105, 103, 32, 102, 117, 110, 99, 32, 61, 32, 115, 99, 97, 114, 121, 32, 102, 117, 110, 99, 32, 109, 117, 97, 104, 97, 104, 97, 104, 97};
    char c[32] = {24, 100, -27, 18, -78, 62, 25, 47, 3, -90, -23, -41, -101, 48, 27, 55, 12, -127, -82, -128, -64, -104, 126, -40, -59, 72, -48, 106, -124, 26, -90, -93};
    char s[32] = {0,};
    char x[32] = {0,};
    printf("Enter flag: ");
    scanf("%s", s);
    int i, j;
    scary_structure sha3;
    uint8_t buf[32];
    scary_1(&sha3, 32);
    scary_2(&sha3, key, 31);
    scary_3(&sha3);
    for (j = 0; j < 512; j += 32) { // output. discard bytes 0..479
        scary_4(&sha3, buf, 32); 
    }
    scary_4(&sha3, x, 32);
    for (i = 0; i < 32; i++) {
        s[i] ^= x[i];
        if (s[i] != c[i]) {
            printf("Nah\n");
            return 0;
        }
    }
    printf("Correct!\n");
}