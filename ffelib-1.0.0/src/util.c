/*
 * util.c
 *
 *  Created on: 2015/03/18
 *      Author: h_ksk
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <gmp.h>
#include "sha1.h"


#define SIZE_MAX_r 100000000000000000

int hash_to_bytes(unsigned char *input_buf, int input_len, int hash_size, unsigned char* output_buf, unsigned int hash_num);
void gen_random(mpz_t *r, gmp_randstate_t s, mpz_t order);
ssize_t read_file(FILE *f, char** out);

//libfencのutil.cから拝借

/*!
 * Hash a null-terminated string to a byte array.
 *
 * @param input_buf		The input buffer.
 * @param input_len		The input buffer length (in bytes).
 * @param hash_len		Length of the output hash (in bytes).
 * @param output_buf	A pre-allocated output buffer.
 * @param hash_num		Index number of the hash function to use (changes the output).
 * @return				FENC_ERROR_NONE or an error code.
 */

int hash_to_bytes(unsigned char *input_buf, int input_len, int hash_size, unsigned char* output_buf, unsigned int hash_num)
{
	SHA1Context sha_context;

	unsigned int block_hdr[2];

	/* Compute an arbitrary number of SHA1 hashes of the form:
	 * output_buf[0...19] = SHA1(hash_num || 0 || input_buf)
	 * output_buf[20..39] = SHA1(hash_num || 1 || output_buf[0...19])
	 * ...
	 */
	block_hdr[0] = hash_num;
	for (block_hdr[1] = 0; hash_size > 0; (block_hdr[1])++) {
		/* Initialize the SHA1 function.	*/
		SHA1Reset(&sha_context);

		SHA1Input(&sha_context, (unsigned char*)&(block_hdr[0]), sizeof(block_hdr));
		SHA1Input(&sha_context, input_buf, input_len);

		SHA1Result(&sha_context);
		if (hash_size <= 20) {
			memcpy(output_buf, sha_context.Message_Digest, hash_size);
			hash_size = 0;
		} else {
			memcpy(output_buf, sha_context.Message_Digest, 20);
			input_buf = output_buf;
			hash_size -= 20;
			output_buf += 20;
		}
	}

	return 0;
}

//Fq上のランダムな値を返す
void gen_random(mpz_t *r, gmp_randstate_t s, mpz_t order) {
    mpz_init(*r);
    mpz_urandomm(*r, s, order);
    return;
}


ssize_t read_file(FILE *f, char** out) {
    ssize_t MAX_LEN = SIZE_MAX_r * 4;
    if(f != NULL) {
        /* See how big the file is */
        fseek(f, 0L, SEEK_END);
        ssize_t out_len = ftell(f);
        printf("out_len: %zd\n", out_len);
        if(out_len <= MAX_LEN) {
            /* allocate that amount of memory only */
            if((*out = (char *) malloc(out_len+1)) != NULL) {
                memset(*out, 0, out_len+1);
                fseek(f, 0L, SEEK_SET);
                fread(*out, sizeof(char), out_len, f);
                return out_len;
            }
        }
    }
    return 0;
}

