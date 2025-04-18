/*
 * Name: Yurii Sykal
 * Student Number: C23512523
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rijndael.h"

// This is the S-Box. It’s used to substitute bytes in AES encryption.
const unsigned char sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

// This is the inverse S-Box. It's used to reverse the substitution when decrypting.
const unsigned char rsbox[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

// These are round constants used during the key expansion step.
const unsigned char Rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// This function multiplies two numbers in GF(2^8).
static unsigned char gf_mul(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        unsigned char hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

/*
 * Operations used when encrypting a block
 */
// This replaces each byte in the block with a value from the S-box.
void sub_bytes(unsigned char *block) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
      block[i] = sbox[block[i]];
    }
}

// This shifts the rows of the block to the left, each by a different amount
void shift_rows(unsigned char *block) {
    unsigned char temp;
    temp = block[1]; block[1] = block[5]; block[5] = block[9]; block[9] = block[13]; block[13] = temp;
    temp = block[2]; block[2] = block[10]; block[10] = temp;
    temp = block[6]; block[6] = block[14]; block[14] = temp;
    temp = block[15]; block[15] = block[11]; block[11] = block[7]; block[7] = block[3]; block[3] = temp;
}

// This mixes the columns of the block to spread the bytes out.
void mix_columns(unsigned char *block) {
    unsigned char tmp[4];
    for (int i = 0; i < 4; i++) {
        tmp[0] = block[i*4+0];
        tmp[1] = block[i*4+1];
        tmp[2] = block[i*4+2];
        tmp[3] = block[i*4+3];
        block[i*4+0] = gf_mul(tmp[0],2) ^ gf_mul(tmp[1],3) ^ tmp[2] ^ tmp[3];
        block[i*4+1] = tmp[0] ^ gf_mul(tmp[1],2) ^ gf_mul(tmp[2],3) ^ tmp[3];
        block[i*4+2] = tmp[0] ^ tmp[1] ^ gf_mul(tmp[2],2) ^ gf_mul(tmp[3],3);
        block[i*4+3] = gf_mul(tmp[0],3) ^ tmp[1] ^ tmp[2] ^ gf_mul(tmp[3],2);
    }
}

/*
 * Operations used when decrypting a block
 */
// This reverses the byte substitution using the inverse S-box
void invert_sub_bytes(unsigned char *block) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
      block[i] = rsbox[block[i]];
    }
}

// This undoes the row shifting from encryption by rotating in the opposite direction.
void invert_shift_rows(unsigned char *block) {
    unsigned char temp;
    temp = block[13]; block[13] = block[9]; block[9] = block[5]; block[5] = block[1]; block[1] = temp;
    temp = block[2]; block[2] = block[10]; block[10] = temp;
    temp = block[6]; block[6] = block[14]; block[14] = temp;
    temp = block[3]; block[3] = block[7]; block[7] = block[11]; block[11] = block[15]; block[15] = temp;
}

// This undoes the column mixing from encryption using different constants.
void invert_mix_columns(unsigned char *block) {
    unsigned char tmp[4];
    for (int i = 0; i < 4; i++) {
        tmp[0] = block[i*4+0];
        tmp[1] = block[i*4+1];
        tmp[2] = block[i*4+2];
        tmp[3] = block[i*4+3];
        block[i*4+0] = gf_mul(tmp[0],0x0e) ^ gf_mul(tmp[1],0x0b) ^ gf_mul(tmp[2],0x0d) ^ gf_mul(tmp[3],0x09);
        block[i*4+1] = gf_mul(tmp[0],0x09) ^ gf_mul(tmp[1],0x0e) ^ gf_mul(tmp[2],0x0b) ^ gf_mul(tmp[3],0x0d);
        block[i*4+2] = gf_mul(tmp[0],0x0d) ^ gf_mul(tmp[1],0x09) ^ gf_mul(tmp[2],0x0e) ^ gf_mul(tmp[3],0x0b);
        block[i*4+3] = gf_mul(tmp[0],0x0b) ^ gf_mul(tmp[1],0x0d) ^ gf_mul(tmp[2],0x09) ^ gf_mul(tmp[3],0x0e);
    }
}

/*
 * This operation is shared between encryption and decryption
 */
void add_round_key(unsigned char *block, unsigned char *round_key) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
      block[i] ^= round_key[i];
    }
}

/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */

/*
 * This function creates all the round keys from the original key.
 * AES needs 11 round keys, and this function generates them all.
 */
void expand_key(unsigned char *cipher_key, unsigned char *round_keys) {
    unsigned char temp[4];
    int i = 0;
    memcpy(round_keys, cipher_key, KEY_SIZE);
    i = KEY_SIZE;
    while (i < BLOCK_SIZE*(NUM_ROUNDS+1)) {
        memcpy(temp, round_keys + i - 4, 4);
        if (i % KEY_SIZE == 0) {
            unsigned char t = temp[0];
            temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
            temp[0] ^= Rcon[i/KEY_SIZE];
        }
        for (int j = 0; j < 4; j++) {
            round_keys[i] = round_keys[i - KEY_SIZE] ^ temp[j];
            i++;
        }
    }
}

/*
 * The implementations of the functions declared in the
 * header file should go here
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {
    unsigned char state[BLOCK_SIZE];  // Temporary block for processing
    unsigned char *output = malloc(BLOCK_SIZE);  // Allocate space for encrypted output
    unsigned char round_keys[BLOCK_SIZE * (NUM_ROUNDS + 1)];  // Expanded keys for all AES rounds

    memcpy(state, plaintext, BLOCK_SIZE);  // Copy plaintext into state
    expand_key((unsigned char*)key, round_keys);  // Generate round keys from the original key

    add_round_key(state, round_keys);  // Initial round key addition (Round 0)

    // Perform main AES rounds (Rounds 1 to 9 for AES-128)
    for (int round = 1; round < NUM_ROUNDS; round++) {
        sub_bytes(state);  // Apply S-box substitution to each byte
        shift_rows(state);  // Shift each row of the state matrix
        mix_columns(state);  // Mix each column using matrix multiplication
        add_round_key(state, round_keys + round*BLOCK_SIZE);  // Add the round key
    }

    // Final round (Round 10 for AES-128) - no MixColumns
    sub_bytes(state);  // Final substitution
    shift_rows(state);  // Final row shifting
    add_round_key(state, round_keys + NUM_ROUNDS*BLOCK_SIZE);  // Add final round key

    memcpy(output, state, BLOCK_SIZE);  // Copy the final state to output buffer
    return output;  // Return pointer to the encrypted block
}

unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key) {
    unsigned char state[BLOCK_SIZE];  // Temporary block for processing
    unsigned char *output = malloc(BLOCK_SIZE);  // Allocate space for decrypted output
    unsigned char round_keys[BLOCK_SIZE * (NUM_ROUNDS + 1)];  // Expanded keys for all AES rounds

    memcpy(state, ciphertext, BLOCK_SIZE);  // Copy ciphertext into state
    expand_key((unsigned char*)key, round_keys);  // Generate round keys from the original key

    add_round_key(state, round_keys + NUM_ROUNDS*BLOCK_SIZE);  // Start decryption with final round key

    // Perform main AES rounds in reverse (Rounds 9 to 1)
    for (int round = NUM_ROUNDS - 1; round >= 1; round--) {
        invert_shift_rows(state);  // Reverse the row shifting
        invert_sub_bytes(state);  // Reverse the byte substitution
        add_round_key(state, round_keys + round*BLOCK_SIZE);  // Add the corresponding round key
        invert_mix_columns(state);  // Reverse the column mixing
    }

    // Final decryption round (Round 0) - no invert_mix_columns
    invert_shift_rows(state);  // Final reverse row shift
    invert_sub_bytes(state);  // Final reverse substitution
    add_round_key(state, round_keys);  // Add the original encryption key

    memcpy(output, state, BLOCK_SIZE);  // Copy the final state to output buffer
    return output;  // Return pointer to the decrypted block
}

