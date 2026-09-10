/* Independent vectors from the repository's original x86 crypto primitives. */
#include "../../skyauth4_dll/skyauth4_dll/crypto/sha1.c"
#include "../../skyauth4_dll/skyauth4_dll/crypto/rijndael.c"

static void print_hex(const unsigned char *data, int length)
{
    int i;
    for (i = 0; i < length; i++) printf("%02X", data[i]);
    printf("\n");
}

int main(void)
{
    unsigned char material[192], output[49], key_bytes[32];
    SHA1_state sha = SHA1_INIT;
    u32 key[8], counter[4], pad[4], schedule[60], n = 0;
    int i, iv, offset, j;
    for (i = 0; i < 192; i++) material[i] = (unsigned char)i;
    material[0] = 1;
    SHA1_update(&sha, &n, 4);
    SHA1_update(&sha, material, 192);
    SHA1_end(&sha);
    memcpy(key, sha.hash, 20);
    n = 0x01000000;
    SHA1_init(&sha);
    SHA1_update(&sha, &n, 4);
    SHA1_update(&sha, material, 192);
    SHA1_end(&sha);
    memcpy(key + 5, sha.hash, 12);
    for (i = 0; i < 8; i++) ((u32*)key_bytes)[i] = _bswap32(key[i]);
    print_hex(key_bytes, 32);
    aes_256_setkey(key, schedule);
    for (iv = 0; iv <= 1; iv++)
    {
        counter[0] = counter[1] = (u32)iv;
        counter[2] = counter[3] = 0;
        for (offset = 0; offset < 49; offset += 16)
        {
            aes_256_encrypt(counter, pad, schedule);
            for (j = 0; j < 16 && offset + j < 49; j++)
                output[offset + j] = (unsigned char)((offset + j) ^ ((unsigned char*)pad)[j ^ 3]);
            counter[3]++;
        }
        print_hex(output, 49);
    }
    return 0;
}
