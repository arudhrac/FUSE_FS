

#ifndef ENCRYPTFS_H
#define ENCRYPTFS_H

#include <stdint.h>
#include <limits.h>
#include "crypto.h"

#define EFS_CONFIG_FILE   ".encryptfs"
#define EFS_MAGIC         "ENCRYPTFS1"
#define EFS_MAGIC_LEN     10


typedef struct {
    char    backing[PATH_MAX]; 
    uint8_t key[EFS_KEY_LEN];  
} efs_state_t;

#endif 
