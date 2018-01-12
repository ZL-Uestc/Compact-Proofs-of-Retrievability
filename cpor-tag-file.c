
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>//轻松获取文件属性
#include <sys/mman.h>
#include <sys/time.h>//时间函数，精确到微秒
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "cpor.h"

// OK, forgive my including .c file directly.
#include "cpor-util.c"

BIGNUM *p;
int n;
BIGNUM *alpha_arr[CPOR_S];//CPOR_S表示的是一个块内扇区的个数
unsigned char kprf[CPOR_PRF_KEY_BYTES];//伪随机函数key的大小，使用的是HAMC—SHA1
off_t file_size;//size in bytes, for regular files
struct timeval start,end;//用于记录执行时间的
long timeuse;

void usage(void)
{
    printf("Usage: cpor-tag-file <file-name>.\n");
}

int write_to_metadata_file(const char *file_name)
{
    FILE *file;
    char *metafile;
    
    metafile = (char *)malloc(strlen(file_name) + strlen(CPOR_META_FILE_SUFFIX) + 1);
    assert(metafile);
    memcpy(metafile, file_name, strlen(file_name));
    strcpy(metafile + strlen(file_name), CPOR_META_FILE_SUFFIX);
    file = fopen(metafile, "wb");
    free(metafile);
    if (!file) {
        fprintf(stderr, "Failed to create metadata file.\n");
        return -1;
    }
    // write p to file.
    if (write_one_Zp_elem(p, file)) {
        fprintf(stderr, "Failed to write p to file.\n");
        goto error;
    }
    // write n to file.
    if (fwrite(&n, sizeof(n), 1, file) != 1) {
        fprintf(stderr, "Failed to write n to file.\n");
        goto error;
    }
    // write kprf to file.
    if (fwrite(kprf, sizeof(kprf), 1, file) != 1) {
        fprintf(stderr, "Failed to write kprf to file.\n");
        goto error;
    }
    // write alpha series to file.
    int i;
    for (i = 0; i < CPOR_S; i++) {
        if (write_one_Zp_elem(alpha_arr[i], file)) {
            fprintf(stderr, "Failed to write alpha series to file.\n");
            goto error;
        }
    }

    fclose(file);
    return 0;
error:
    fclose(file);
    return -1;
}

int generate_metadata_file(const char *file_name)
{
    BN_CTX *ctx;
    int i;

    // Generate p.
    ctx = BN_CTX_new();//申请一个新的上下文结构，存储中间过程
    assert(ctx);
    int retries = 64;
    int flag = 0;
    for (i = 0; i < retries; i++) {
        if (BN_generate_prime(p, CPOR_PRIME_BITS, 1, NULL, NULL, NULL, NULL)//产生CPOR_PRIME_BITS bits位的素数
            && BN_is_prime(p, BN_prime_checks, NULL, ctx, NULL)//判断是否为素数
            && (BN_num_bits(p) == CPOR_PRIME_BITS)) {
            flag = 1;
            break;
        }
    }
    BN_CTX_free(ctx);
    if (!flag) {
        fprintf(stderr, "Generate large prime number failed.\n");
        return -1;
    }
    // Generate PRF key
    if (!RAND_bytes(kprf, sizeof(kprf))) {
        fprintf(stderr, "RAND_bytes failed.\n");
        return -1;
    }
    // Generate the alpha series
    for (i = 0; i < CPOR_S; i++) {
        BIGNUM *ptr = alpha_arr[i];
        if (!BN_rand_range(ptr, p)) {
            fprintf(stderr, "BN_rand_range failed.\n");
            return -1;
        }
    }

    return write_to_metadata_file(file_name);
}

BIGNUM *process_one_block(int block_idx, const unsigned char *curr, int block_size)
{
    int j, ret;
    unsigned char mac[CPOR_MAC_OUTPUT_BYTES];
    BIGNUM *sigma = NULL, *f_prf = NULL, *mij = NULL;
    BIGNUM *sigma_alpha_mij = NULL;

    DEBUG_PRINT("processing block #%d.\n", block_idx);
    //BN_new()  生成一个新的BIGNUM结构
    sigma = BN_new();
    assert(sigma);
    f_prf = BN_new();
    assert(f_prf);
    mij = BN_new();
    assert(mij);
    sigma_alpha_mij = BN_new();
    assert(sigma_alpha_mij);
    BN_CTX *ctx = BN_CTX_new();//申请新的上下文结构
    assert(ctx);
    BN_CTX_init(ctx);//将所有的项赋值为0
    HMAC_CTX mac_ctx;
    HMAC_CTX_init(&mac_ctx);

    // calc the first term.
    HMAC_Init(&mac_ctx, kprf, sizeof(kprf), EVP_sha1());
    HMAC_Update(&mac_ctx, (unsigned char *)&block_idx, sizeof(block_idx));
    unsigned usize;
    HMAC_Final(&mac_ctx, mac, &usize);
    assert(usize == CPOR_MAC_OUTPUT_BYTES);
    f_prf = BN_bin2bn(mac, usize, f_prf);
    assert(f_prf);
    HMAC_CTX_cleanup(&mac_ctx);

    // calc the second term.
    ret = BN_zero(sigma_alpha_mij);
    assert(ret);
    for (j = 0; j < CPOR_S; j++) {
        mij = BN_bin2bn(curr, CPOR_SECTOR_SIZE, mij);//sector size为8bytes 将curr中的SECTOR位的正整数转化为大整数
        assert(mij);
        ret = BN_mod_mul(mij, alpha_arr[j], mij, p, ctx);//mij = (alpha_arr[j] * mij) % p
        assert(ret);
        ret = BN_mod_add(sigma_alpha_mij, sigma_alpha_mij, mij, p, ctx);//sigma_alpha_mij = (sigma_alpha_mij + mij) % p
        assert(ret);
        curr += CPOR_SECTOR_SIZE;
    }

    // now f_prf holds the first term and sigma_alpha_mij holds the second term.
    ret = BN_mod_add(sigma, f_prf, sigma_alpha_mij, p, ctx);//sigma = (f_prf + sigma_alpha_mij) % p
    assert(ret);

    BN_CTX_free(ctx);//释放上下文结构
    BN_free(f_prf);
    BN_free(mij);
    BN_free(sigma_alpha_mij);

    return sigma;
}

int generate_tag_file(const char *file_name)
{
    int fd, i;
    void *addr;
    unsigned char *curr;
    FILE *file;
    char *tagfile;
    
    tagfile = (char *)malloc(strlen(file_name) + strlen(CPOR_TAG_FILE_SUFFIX) + 1);
    assert(tagfile);
    memcpy(tagfile, file_name, strlen(file_name));
    strcpy(tagfile + strlen(file_name), CPOR_TAG_FILE_SUFFIX);

    // map the data file into memory.
    fd = open(file_name, O_RDONLY);
    if (fd < 0) {
        perror("open: ");
        return -1;
    }
    addr = (unsigned char *)mmap(NULL, file_size, PROT_READ,//内存保护机制，页内容可以被读取
            MAP_PRIVATE, fd, 0);//fd有效的文件描述词，一般由open()函数返回
    if ((void *)addr == MAP_FAILED) {
        perror("mmap: ");
        return -1;
    }
    close(fd);
    // Open the tag file for write.
    file = fopen(tagfile, "wb");
    free(tagfile);
    if (!file) {
        fprintf(stderr, "Failed to create tag file.\n");
        goto error;
    }

    // process each block and write tag to tagfile.
    curr = addr;
    for (i = 0; i < n; i++) {
        BIGNUM *sigma = process_one_block(i, curr, CPOR_BLOCK_SIZE);
        assert(sigma);
        curr += CPOR_BLOCK_SIZE;
        // write sigma to file.
        if (write_one_Zp_elem(sigma, file)) {
            BN_free(sigma);
            goto error;
        }
        BN_free(sigma);//释放一个BIGNUM结构
    }

    munmap(addr, file_size);
    return 0;
error:
    munmap(addr, file_size);
    return -1;
}
//确定大整数p,以及分配给每个文件块扇区前的随机数α
void init(void)
{
    int i;
    // allocate p
    p = BN_new();
    assert(p);
    // allocate alpha series.
    for (i = 0; i < CPOR_S; i++) {
        BIGNUM *ptr = BN_new();
        assert(ptr);
        alpha_arr[i] = ptr;
    }
}
    
int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage();
        return -1;
    }
    char *file_name = argv[1];//获取文件名
    struct stat st;

    // init global variables.
    init();

    // get the file size.
    if (stat(file_name, &st) < 0) {
        perror("stat: ");
        return -1;
    }
    file_size = st.st_size;
    // How many blocks in the file?
    // n = (file_size + CPOR_BLOCK_SIZE - 1) / CPOR_BLOCK_SIZE;
    n = file_size / CPOR_BLOCK_SIZE;//文件大小 4096bytes

    DEBUG_PRINT("file_size: %ld KB, blocks: %d.\n", file_size / 1024, n);

    // generate the metadata file.
    printf("Generating metadata file %s%s...", file_name, CPOR_META_FILE_SUFFIX);
    gettimeofday(&start,NULL);
    if (generate_metadata_file(file_name)) {
        fprintf(stderr, "Generate metadata file failed.\n");
        return -1;
    }
    gettimeofday(&end,NULL);
    timeuse = 1000000*(end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);
    printf("Done. Time of generating metadata file is %fs\n",timeuse/1000000.0);

    // generate tag for each block, and write to tag file.
    printf("Generating tag file %s%s...", file_name, CPOR_TAG_FILE_SUFFIX);
    gettimeofday(&start,NULL);
    if (generate_tag_file(file_name)) {
        fprintf(stderr, "Generate tag file failed.\n");
        return -1;
    }
    gettimeofday(&end,NULL);
    timeuse = 1000000*(end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);
    printf("Done. Time of generating tag file is %fs\n",timeuse/1000000.0);
    return 0;
}

