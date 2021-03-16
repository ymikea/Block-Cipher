#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <math.h>
#include <unistd.h>
#include <stdint.h>

#define OFFSET 8
uint8_t subKeys[12];
int shift = 0;
int Round;
int Encryption;
int Decryption;

uint8_t ftable[256] = {
    0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4, 0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1, 0xaf, 0xf9,
    0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e, 0x52, 0x95, 0xd9, 0x1e, 0x4e, 0x38, 0x44, 0x28,
    0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60, 0x68, 0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53,
    0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19, 0x7c, 0xae, 0xe5, 0xf5, 0xf7, 0x16, 0x6a, 0xa2,
    0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b, 0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8,
    0x55, 0xb9, 0xda, 0x85, 0x3f, 0x41, 0xbf, 0xe0, 0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90,
    0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76,
    0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20, 0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47, 0x4a, 0x1d,
    0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43, 0x27, 0xd2, 0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18,
    0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa, 0xc8, 0x74, 0xdc, 0xc9, 0x5d, 0x5c, 0x31, 0xa4,
    0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87, 0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40,
    0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4, 0xfd, 0x3b, 0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5,
    0xad, 0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0, 0x29, 0x79, 0x71, 0x7e, 0xff, 0x8c, 0x0e, 0xe2,
    0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1, 0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8,
    0x08, 0x77, 0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5, 0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6, 0xbb, 0xac,
    0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3, 0xbd, 0xa8, 0x3a, 0x01, 0x05, 0x59, 0x2a, 0x46};

uint64_t whiteNing_hex(uint64_t key, uint64_t text){
    return key ^ text;
}

uint64_t RoL(uint64_t n, unsigned int d, unsigned int bit){
    return (n << d) | (n >> (bit - d));
}

uint64_t RoR(uint64_t n, unsigned int d, unsigned int bit){
    return (n >> d) | (n << (bit - d));
}

void split_hex(uint64_t key, uint64_t *bit_keys, int bitlen, int size){
    int bit = 0;
    int mask;
    switch (bitlen)
    {
    case (8):
        mask = 0xFF;
        break;
    case (16):
        mask = 0xFFFF;
        break;
    }

    for (int i = size - 1; i >= 0; i--)
    {
        uint64_t c = (key >> bit) & mask;
        bit_keys[i] = c;
        bit = bit + bitlen;
    }
}

uint16_t G(uint16_t R1, uint8_t k0, uint8_t k1, uint8_t k2, uint8_t k3, int round){
    uint64_t R[2];
    split_hex(R1, R, 8, 2);
    uint8_t g1 = R[0];
    uint8_t g2 = R[1];
    uint8_t g3 = (ftable[g2 ^ k0] ^ g1);
    uint8_t g4 = (ftable[g3 ^ k1] ^ g2);
    uint8_t g5 = (ftable[g4 ^ k2] ^ g3);
    uint8_t g6 = (ftable[g5 ^ k3] ^ g4);
    uint16_t T = (g5 << 8) | (g6);
    return T;
}

void K(uint64_t *key){
    if (Encryption)
    {
        *key = RoL(*key, 1, 64);
    }
    if (Decryption)
    {
        *key = RoR(*key, 1, 64);
    }
}

uint64_t concat(uint64_t k1, uint64_t k2, unsigned int bits){
    uint64_t conc = (k1 << bits) | (k2);
    return conc;
}

void F(uint64_t *R, uint8_t *sub_key, uint16_t *f){
    uint16_t t0 = G(R[0], sub_key[0], sub_key[1], sub_key[2], sub_key[3], Round);
    uint16_t t1 = G(R[1], sub_key[4], sub_key[5], sub_key[6], sub_key[7], Round);
    uint16_t conc_k8_k9 = concat(sub_key[8], sub_key[9], 8);
    uint16_t conc_k10_k11 = concat(sub_key[10], sub_key[11], 8);
    if (Encryption)
    {
        f[0] = ((t0 + 2 * (t1) + conc_k8_k9)) % (uint64_t)pow(2, 16);
        f[1] = ((2 * t0 + t1 + conc_k10_k11)) % (uint64_t)pow(2, 16);
    }
    else
    {
        f[0] = ((t0 + 2 * (t1) + conc_k8_k9)) % (uint64_t)pow(2, 16);
        f[1] = ((2 * t0 + t1 + conc_k10_k11)) % (uint64_t)pow(2, 16);
    }
}

uint64_t lastSwap(uint64_t key, uint64_t keyTxt_hex){
    uint16_t d = (key >> 16) & 0xFFFF;
    uint16_t f = (key)&0xFFFF;
    uint16_t c = (key >> 48) & 0xFFFF;
    uint16_t e = (key >> 32) & 0xFFFF;
    uint32_t df = concat(d, f, 16);
    uint32_t ce = concat(c, e, 16);
    uint64_t final = concat(df, ce, 32);
    uint64_t wh_key1 = whiteNing_hex(final, keyTxt_hex);
    return wh_key1;
}

void generateSub(uint64_t keyTxt_hex, uint8_t *k){
    if (Encryption){
        for (int i = 0; i < 12; i++){
            K(&keyTxt_hex);
            unsigned int x = 4 * Round + shift;
            subKeys[i] = k[x % 8];
            shift = (shift + 1) % 4;
        }
    }
    if (Decryption){
        for (int i = 11; i >= 0; i--){
            shift = (shift + 3) % 4;
            unsigned int x = 4 * (15 - Round) + shift;
            subKeys[i] = k[x % 8];
            K(&keyTxt_hex);
        }
    }
}

int main(int argc, char *argv[]){
    FILE *fp_plain, *fp_key, *fp_cipher;
    char keyTxt_buff[17];
    int opt, readBits;
    uint64_t R[4];
    uint16_t f[2];
    while ((opt = getopt(argc, argv, "dk:ek:in:out:")) != -1){
        switch (opt){
        case 'd':
            Decryption = 1;
            break;
        case 'e':
            Encryption = 1;
            break;
        case 'k':
            fp_key = fopen(optarg, "r");
            break;
        case 'i':
        case 'n':
            fp_plain = fopen(optarg, "rb");
            break;
        case 'o':
        case 'u':
        case 't':
            fp_cipher = fopen(optarg, "w+b");
            break;
        }
    }

    fread(keyTxt_buff, 16, 1, fp_key);
    uint64_t keyTxt_hex = (uint64_t)strtoul(keyTxt_buff, NULL, 16);

    uint8_t *k = (uint8_t *)&keyTxt_hex;

    if (Encryption){
        uint64_t plainTxt_buff;
        while ((readBits = fread(&plainTxt_buff, 1, 8, fp_plain)) > 0){
            uint64_t plainTxt_hex = plainTxt_buff;

            if (readBits < 8){
                uint64_t NumPad = (8 - readBits) * 2;
                plainTxt_hex = plainTxt_hex << NumPad * 4;
                plainTxt_hex = plainTxt_hex + NumPad / 2;
            }

            uint64_t whiteNed_key = whiteNing_hex(keyTxt_hex, plainTxt_hex);
            for (int y = 0; y < 16; y++){
                split_hex(whiteNed_key, R, 16, 4);
                generateSub(keyTxt_hex, k);
                F(R, subKeys, f);
                uint16_t r2 = RoR(R[2] ^ f[0], 1, 16);
                uint16_t r3 = RoL(R[3], 1, 16) ^ f[1];
                uint32_t r = concat(r2, r3, 16);
                uint32_t r4 = concat(R[0], R[1], 16);
                whiteNed_key = concat(r, r4, 32);
                Round++;
            }

            uint64_t swapped_whiteNed_key = lastSwap(whiteNed_key, keyTxt_hex);

            char Hex_Str[17];
            sprintf(Hex_Str, "%16llx", swapped_whiteNed_key);
            fwrite(Hex_Str, sizeof(Hex_Str) - 1, 1, fp_cipher);
            memset(&plainTxt_buff, 0, sizeof(plainTxt_buff));
        }
    }

    if (Decryption){
        char plainTxt_buff[17];
        while ((readBits = fread(plainTxt_buff, 1, 16, fp_plain)) > 0){
            uint64_t plainTxt_hex = (uint64_t)strtoul(plainTxt_buff, NULL, 16);
            uint64_t whiteNed_key = whiteNing_hex(plainTxt_hex, keyTxt_hex);
            for (size_t y = 0; y < 16; y++){
                split_hex(whiteNed_key, R, 16, 4);
                generateSub(keyTxt_hex, k);
                F(R, subKeys, f);

                uint16_t d_r2 = RoL(R[2], 1, 16) ^ f[0];
                uint16_t d_r3 = RoR(R[3] ^ f[1], 1, 16);
                uint32_t d_r = concat(d_r2, d_r3, 16);
                uint32_t d_r4 = concat(R[0], R[1], 16);
                whiteNed_key = concat(d_r, d_r4, 32);
                Round++;
            }

            uint64_t swapped_whiteNed_key = lastSwap(whiteNed_key, keyTxt_hex);
            uint8_t *swapped_8bitkey = (uint8_t *)&swapped_whiteNed_key;
            int length = sizeof(uint64_t);
            if ((swapped_8bitkey[0] < 0x08) && (swapped_8bitkey[0] > 0x00)){
                int shift_pos = swapped_8bitkey[0] * 8;
                length = 8 - swapped_8bitkey[0];
                swapped_8bitkey[0] = 0x00;
                swapped_whiteNed_key = swapped_whiteNed_key >> shift_pos;
            }
            fwrite(&swapped_whiteNed_key, length, 1, fp_cipher);
            memset(&plainTxt_buff, 0, sizeof(plainTxt_buff));
        }
    }

    return 0;
}
