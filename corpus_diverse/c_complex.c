/* Dense C sample: bitfields, unions, nested structs, enums, function
 * pointers, varargs, wide/utf16 strings, long double, packed layout. */
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

typedef enum _Color : int8_t { RED = -1, GREEN = 0, BLUE = 2, ALPHA = 127 } Color;

typedef struct _PackedHeader {
    uint16_t magic;
    uint16_t version : 4;
    uint16_t flags : 9;
    uint16_t reserved : 3;
    uint32_t payloadLen;
    uint64_t checksum;
} __attribute__((packed)) PackedHeader;

typedef union _PacketBody {
    uint8_t raw[16];
    uint32_t words[4];
    struct {
        float x, y;
        double magnitude;
    } vector;
} PacketBody;

typedef struct _Node {
    struct _Node* next;
    struct _Node* prev;
    Color color;
    uint8_t heightCm;
    char tag[12];
    PacketBody body;
} Node;

typedef int (*Comparator)(const void*, const void*);
typedef void (*Formatter)(char* out, size_t cap, const char* fmt, ...);

static int compareTags(const void* a, const void* b) {
    const Node* na = (const Node*)a;
    const Node* nb = (const Node*)b;
    return strcmp(na->tag, nb->tag);
}

static void formatLine(char* out, size_t cap, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(out, cap, fmt, ap);
    va_end(ap);
}

static long double estimateArea(long double radius) {
    return 3.14159265358979323846L * radius * radius;
}

static uint64_t fnv1a(const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    uint64_t hash = 1469598103934665603ULL;
    for (size_t i = 0; i < len; ++i) {
        hash ^= p[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

int main(int argc, char** argv) {
    PackedHeader hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = 0xC0DE;
    hdr.version = 7;
    hdr.flags = 0x155;
    hdr.payloadLen = sizeof(PacketBody);
    hdr.checksum = fnv1a("enigma-diverse-corpus", 21);

    PacketBody body;
    body.vector.x = 1.5f;
    body.vector.y = 2.5f;
    body.vector.magnitude = 3.9;

    Node nodes[4];
    const char* tags[4] = {"alpha", "bravo", "charlie", "delta"};
    for (int i = 0; i < 4; ++i) {
        nodes[i].next = (i + 1 < 4) ? &nodes[i + 1] : NULL;
        nodes[i].prev = (i > 0) ? &nodes[i - 1] : NULL;
        nodes[i].color = (Color)(i - 1);
        nodes[i].heightCm = (uint8_t)(10 * (i + 1));
        strcpy(nodes[i].tag, tags[i]);
        nodes[i].body.words[0] = (uint32_t)i;
    }

    Comparator cmp = compareTags;
    qsort(nodes, 4, sizeof(Node), cmp);

    Formatter fmt = formatLine;
    char line[128];
    fmt(line, sizeof(line), "magic=%04x v=%u flags=%03x sum=%016llx",
        (unsigned)hdr.magic, (unsigned)hdr.version, (unsigned)hdr.flags,
        (unsigned long long)hdr.checksum);

    wchar_t wline[64];
    swprintf(wline, 64, L"area=%.3f nodes=%d", (double)estimateArea(2.0L), 4);

    printf("%s\n", line);
    wprintf(L"%ls\n", wline);
    for (int i = 0; i < 4; ++i) {
        printf("node[%d] tag=%-8s color=%d mag=%.2f\n", i, nodes[i].tag,
               (int)nodes[i].color, nodes[i].body.vector.magnitude);
    }
    return argc > 5 ? EXIT_FAILURE : EXIT_SUCCESS;
}
