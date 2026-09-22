#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static size_t allocation_budget = 2 * 1024 * 1024;
static void *bounded_malloc(size_t bytes) {
    if (bytes > allocation_budget) exit(20);
    allocation_budget -= bytes;
    return malloc(bytes ? bytes : 1);
}
static void *bounded_realloc(void *ptr, size_t bytes) {
    if (bytes > allocation_budget) exit(20);
    allocation_budget -= bytes;
    return realloc(ptr, bytes ? bytes : 1);
}
#define malloc bounded_malloc
#define realloc bounded_realloc
#include "pack-4142.c"
#include "unpack-4142.c"
#undef malloc
#undef realloc

int main(void) {
    unsigned char input[16385], output[65536], *cursor;
    u32 remaining, budget = 0x50000, length, consumed;
    size_t count = fread(input, 1, sizeof(input), stdin);
    skype_list list = { &list, 0, 0, 0 };
    if (ferror(stdin) || count == 0 || count > 16384 || (input[0] != 0x41 && input[0] != 0x42)) return 2;
    /*
     * 0x41 is already the normalized representation. The Go server only invokes
     * this helper for 0x42 data, but accepting 0x41 here provides a harmless
     * worker-protocol smoke test and mirrors the Windows helper's accepted input.
     */
    if (input[0] == 0x41) {
        consumed = (u32)count;
        if (fwrite(&consumed, 4, 1, stdout) != 1 || fwrite(input, 1, count, stdout) != count) return 8;
        return 0;
    }
    remaining = (u32)count;
    cursor = input;
    if (!unpack_4142((u32*)&list, &cursor, &remaining, NULL, 8, &budget)) return 3;
    consumed = (u32)(cursor - input);
    if (consumed == 0 || consumed > count || consumed + remaining != count) return 4;
    length = pack_4142((u32*)&list, output, 0, sizeof(output));
    if (length == 0 || length > sizeof(output) || output[0] != 0x41) return 7;
    if (fwrite(&consumed, 4, 1, stdout) != 1 || fwrite(output, 1, length, stdout) != length) return 8;
    return 0;
}
