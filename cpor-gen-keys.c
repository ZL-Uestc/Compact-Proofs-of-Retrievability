
#include <openssl/rand.h>
#include <stdio.h>
#include "cpor.h"

int main(int argc, char *argv[])
{
    const char *file_name = CPOR_MASTER_KEYS_FILE;//CPOR_MASTER_KEYS_FILE       "master_keys"
    FILE *file;
    unsigned char kenc[CPOR_ENC_KEY_BYTES];//(value:128/8 = 16 bytes) currently AES-128 is used
    unsigned char kmac[CPOR_MAC_KEY_BYTES];//(value:160/8 = 20 bytes) sha1 is used

    printf("Generating master keys....\n");
    file = fopen(file_name, "wb");
    if (!file) {
        fprintf(stderr, "Create master keys file failed.\n");
        return -1;
    }
    if (!RAND_bytes(kenc, sizeof(kenc))) {//获得随机数，将随机数写入到kenc中
        fprintf(stderr, "RAND_bytes failed.\n");
        return -1;
    }
    if (!RAND_bytes(kmac, sizeof(kmac))) {
        fprintf(stderr, "RAND_bytes failed.\n");
        return -1;
    }
    if(fwrite(kenc, sizeof(kenc), 1, file) != 1) {//size_t fwrite(const void* buffer, size_t size, size_t count, FILE* stream);
                                                  //注意：这个函数以二进制形式对文件进行操作，不局限于文本文件
        fprintf(stderr, "fwrite failed.\n");
        return -1;
    }
    if(fwrite(kmac, sizeof(kmac), 1, file) != 1) {
        fprintf(stderr, "fwrite failed.\n");
        return -1;
    }
    fflush(file);
    fclose(file);
    printf("Done.\n");

    return 0;
}

