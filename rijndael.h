/*
 * Name: Yurii Sykal
 * Student Number: C23512523
 *
 */

 #ifndef RIJNDAEL_H
 #define RIJNDAEL_H
 
 #include <stddef.h>  // For size_t
 #include <string.h>  // For memcpy
 
 #define BLOCK_ACCESS(block, row, col) (block[(row * 4) + col])
 #define BLOCK_SIZE 16
 #define KEY_SIZE 16       // AES-128
 #define NUM_ROUNDS 10     // AES-128 has 10 rounds
 
 /*
  * These should be the main encrypt/decrypt functions (i.e. the main
  * entry point to the library for programmes hoping to use it to
  * encrypt or decrypt data)
  */
 unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key);
 unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key);

 
 #endif // RIJNDAEL_H
 