#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>
#include <fcntl.h>

/* Keep the old decoder out of the server process; all allocations are bounded. */
static size_t allocation_budget = 2 * 1024 * 1024;
static void *bounded_malloc(size_t bytes)
{
    if (bytes > allocation_budget) ExitProcess(20);
    allocation_budget -= bytes;
    return malloc(bytes ? bytes : 1);
}
static void *bounded_realloc(void *ptr, size_t bytes)
{
    if (bytes > allocation_budget) ExitProcess(20);
    allocation_budget -= bytes;
    return realloc(ptr, bytes ? bytes : 1);
}
#define malloc bounded_malloc
#define realloc bounded_realloc
#include "../skypeopensource2/skyauth4_dll/skyauth4_dll/skype/pack-4142.c"
#include "../skypeopensource2/skyauth4_dll/skyauth4_dll/skype/unpack-4142.c"
#undef malloc
#undef realloc

static int describe_list(const skype_list *list, int depth)
{
    u32 i;
    if (depth > 8 || list->things > 4096) return 0;
    for (i = 0; i < list->things; i++)
    {
        const skype_thing *thing = &list->thing[i];
        printf("depth=%d type=%u id=%u", depth, thing->type, thing->id);
        if (thing->type == 0) printf(" value=%u", thing->m);
        else if (thing->type == 3 || thing->type == 4 || thing->type == 6) printf(" bytes=%u", thing->n);
        printf("\n");
        if (thing->type == 5 && !describe_list((const skype_list*)thing->m, depth + 1)) return 0;
    }
    return 1;
}

static int run(int describe)
{
    unsigned char input[16385], *cursor, *output;
    u32 remaining, budget = 65536, length, consumed;
    DWORD old_protection;
    size_t count = fread(input, 1, sizeof(input), stdin);
    skype_list list = { &list, 0, 0, 0 };
    if (ferror(stdin) || count == 0 || count > 16384 || (input[0] != 0x41 && input[0] != 0x42)) return 2;
    remaining = (u32)count;
    cursor = input;
    if (!unpack_4142((u32*)&list, &cursor, &remaining, NULL, 8, &budget)) return 3;
    consumed = (u32)(cursor - input);
    if (consumed == 0 || consumed > count || consumed + remaining != count) return 4;
    if (describe)
    {
        printf("consumed=%u remaining=%u\n", consumed, remaining);
        return describe_list(&list, 0) ? 0 : 5;
    }
    output = (unsigned char*)VirtualAlloc(NULL, 65536 + 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!output || !VirtualProtect(output + 65536, 4096, PAGE_NOACCESS, &old_protection)) return 6;
    length = pack_4142((u32*)&list, output, 0, 65536);
    if (length == 0 || length > 65536 || output[0] != 0x41) return 7;
    /* Little-endian length prefix, followed by one normalized 41 list. */
    if (fwrite(&consumed, 4, 1, stdout) != 1 || fwrite(output, 1, length, stdout) != length) return 8;
    VirtualFree(output, 0, MEM_RELEASE);
    return 0;
}

int main(int argc, char **argv)
{
    int result;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
    if (argc > 2 || (argc == 2 && strcmp(argv[1], "--describe") != 0)) return 1;
    __try { result = run(argc == 2); }
    __except(EXCEPTION_EXECUTE_HANDLER) { result = 21; }
    return result;
}
