

#ifndef EFS_CRYPTO_H
#define EFS_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

/* ─── Size constants ──────────────────────────────────────── */
#define EFS_KEY_LEN       32          /* AES-256: 256-bit key                */
#define EFS_IV_LEN        12          /* GCM nonce: 96-bit (optimal for GCM) */
#define EFS_TAG_LEN       16          /* GCM auth tag: 128-bit               */
#define EFS_SALT_LEN      32          /* PBKDF2 salt: 256-bit                */
#define EFS_HDR_LEN       (EFS_IV_LEN + EFS_TAG_LEN)  /* 28 bytes per file  */
#define EFS_PBKDF2_ITER   200000      /* PBKDF2 iterations (NIST recommends 100k+) */


int efs_generate_salt(uint8_t buf[EFS_SALT_LEN]);

int efs_derive_key(const char *password,
                   const uint8_t salt[EFS_SALT_LEN],
                   uint8_t key_out[EFS_KEY_LEN]);


int efs_encrypt(const uint8_t  key[EFS_KEY_LEN],
                const uint8_t *plaintext,  size_t pt_len,
                uint8_t        iv_out[EFS_IV_LEN],
                uint8_t        tag_out[EFS_TAG_LEN],
                uint8_t       *ciphertext_out);


int efs_decrypt(const uint8_t  key[EFS_KEY_LEN],
                const uint8_t  iv[EFS_IV_LEN],
                const uint8_t  tag[EFS_TAG_LEN],
                const uint8_t *ciphertext, size_t ct_len,
                uint8_t       *plaintext_out);

#endif /* EFS_CRYPTO_H */
