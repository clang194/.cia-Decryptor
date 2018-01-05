#include "decryptor.h"
#include "sha256.h"

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
#include <direct.h>
#include <windows.h>
#define MKDIR(path) _mkdir(path)
#define PATH_SEP '\\'
#else
#include <dirent.h>
#define MKDIR(path) mkdir((path), 0775)
#define PATH_SEP '/'
#endif

void logv(const Options *opt, const char *fmt, ...)
{
    va_list ap;
    if (!opt->verbose) {
        return;
    }
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

uint16_t rd16be(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

uint16_t rd16le(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[1] << 8) | p[0]);
}

uint32_t rd32be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

uint32_t rd32le(const uint8_t *p)
{
    return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) | ((uint32_t)p[1] << 8) | p[0];
}

uint64_t rd64be(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | p[i];
    }
    return v;
}

uint64_t rd64le(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) {
        v = (v << 8) | p[i];
    }
    return v;
}

void wr16be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

uint64_t align_up(uint64_t value, uint64_t alignment)
{
    return (value + alignment - 1) & ~(alignment - 1);
}

static int file_seek_abs(FILE *fp, uint64_t off);
static int file_seek_end(FILE *fp);
static int64_t file_tell(FILE *fp);

int read_exact_at(FILE *fp, uint64_t off, void *buf, size_t len)
{
    if (file_seek_abs(fp, off) != 0) {
        return 0;
    }
    return fread(buf, 1, len, fp) == len;
}

int write_all(FILE *fp, const void *buf, size_t len)
{
    return fwrite(buf, 1, len, fp) == len;
}

static int file_seek_abs(FILE *fp, uint64_t off)
{
#ifdef _WIN32
    return _fseeki64(fp, (__int64)off, SEEK_SET);
#else
    return fseeko(fp, (off_t)off, SEEK_SET);
#endif
}

static int file_seek_end(FILE *fp)
{
#ifdef _WIN32
    return _fseeki64(fp, 0, SEEK_END);
#else
    return fseeko(fp, 0, SEEK_END);
#endif
}

static int64_t file_tell(FILE *fp)
{
#ifdef _WIN32
    return (int64_t)_ftelli64(fp);
#else
    return (int64_t)ftello(fp);
#endif
}

int write_zeros(FILE *fp, uint64_t len)
{
    static const uint8_t zeros[4096] = {0};

    while (len > 0) {
        size_t chunk = len > sizeof(zeros) ? sizeof(zeros) : (size_t)len;
        if (!write_all(fp, zeros, chunk)) {
            return 0;
        }
        len -= chunk;
    }
    return 1;
}

int pad_to_offset(FILE *fp, uint64_t target)
{
    int64_t pos = file_tell(fp);
    if (pos < 0 || (uint64_t)pos > target) {
        return 0;
    }
    return write_zeros(fp, target - (uint64_t)pos);
}

uint64_t get_file_size(FILE *fp)
{
    int64_t cur = file_tell(fp);
    int64_t end;
    if (cur < 0 || file_seek_end(fp) != 0) {
        return 0;
    }
    end = file_tell(fp);
    file_seek_abs(fp, (uint64_t)cur);
    return end < 0 ? 0 : (uint64_t)end;
}

int copy_range(FILE *in, FILE *out, uint64_t off, uint64_t size)
{
    uint8_t *buf = malloc(COPY_CHUNK);
    uint64_t pos = 0;
    int ok = 1;

    if (!buf) {
        return 0;
    }
    while (pos < size) {
        size_t chunk = (size - pos) > COPY_CHUNK ? COPY_CHUNK : (size_t)(size - pos);
        if (!read_exact_at(in, off + pos, buf, chunk) || !write_all(out, buf, chunk)) {
            ok = 0;
            break;
        }
        pos += chunk;
    }
    free(buf);
    return ok;
}

int copy_named_file(FILE *out, const char *path)
{
    FILE *in = fopen(path, "rb");
    uint8_t *buf;
    int ok = 1;

    if (!in) {
        return 0;
    }
    buf = malloc(COPY_CHUNK);
    if (!buf) {
        fclose(in);
        return 0;
    }
    for (;;) {
        size_t n = fread(buf, 1, COPY_CHUNK, in);
        if (n > 0 && !write_all(out, buf, n)) {
            ok = 0;
            break;
        }
        if (n < COPY_CHUNK) {
            if (ferror(in)) {
                ok = 0;
            }
            break;
        }
    }
    free(buf);
    fclose(in);
    return ok;
}

int sha256_named_file(const char *path, uint8_t hash[32], uint64_t *size_out)
{
    FILE *fp = fopen(path, "rb");
    uint8_t *buf;
    sha256_ctx ctx;
    uint64_t total = 0;
    int ok = 1;

    if (!fp) {
        return 0;
    }
    buf = malloc(COPY_CHUNK);
    if (!buf) {
        fclose(fp);
        return 0;
    }
    sha256_init(&ctx);
    for (;;) {
        size_t n = fread(buf, 1, COPY_CHUNK, fp);
        if (n > 0) {
            sha256_update(&ctx, buf, n);
            total += n;
        }
        if (n < COPY_CHUNK) {
            if (ferror(fp)) {
                ok = 0;
            }
            break;
        }
    }
    if (ok) {
        sha256_final(&ctx, hash);
        if (size_out) {
            *size_out = total;
        }
    }
    free(buf);
    fclose(fp);
    return ok;
}

int sig_block_size(uint32_t sig_type)
{
    switch (sig_type) {
        case 0x00010000u:
        case 0x00010003u:
            return 0x240;
        case 0x00010001u:
        case 0x00010004u:
            return 0x140;
        case 0x00010002u:
        case 0x00010005u:
            return 0x7c;
        default:
            return -1;
    }
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    size_t len = strlen(hex);
    if (len != out_len * 2) {
        return 0;
    }
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return 0;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

void hex64_be(char out[17], const uint8_t in[8])
{
    static const char hexdigits[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        out[i * 2] = hexdigits[in[i] >> 4];
        out[i * 2 + 1] = hexdigits[in[i] & 0xf];
    }
    out[16] = 0;
}

int mkdir_p(const char *path)
{
    char *tmp;
    size_t len;

    if (!path || !*path) {
        return 1;
    }
    len = strlen(path);
    tmp = malloc(len + 1);
    if (!tmp) {
        return 0;
    }
    memcpy(tmp, path, len + 1);

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/' || *p == '\\') {
            char old = *p;
            *p = 0;
            if (MKDIR(tmp) != 0 && errno != EEXIST) {
                free(tmp);
                return 0;
            }
            *p = old;
        }
    }
    if (MKDIR(tmp) != 0 && errno != EEXIST) {
        free(tmp);
        return 0;
    }
    free(tmp);
    return 1;
}

char *path_basename_no_ext(const char *path)
{
    const char *base = strrchr(path, '/');
    const char *base2 = strrchr(path, '\\');
    const char *dot;
    size_t len;
    char *out;

    if (!base || (base2 && base2 > base)) {
        base = base2;
    }
    base = base ? base + 1 : path;
    dot = strrchr(base, '.');
    len = dot && dot > base ? (size_t)(dot - base) : strlen(base);

    out = malloc(len + 1);
    if (!out) {
        return NULL;
    }
    memcpy(out, base, len);
    out[len] = 0;
    return out;
}

static char *xstrdup(const char *s)
{
    size_t len = strlen(s);
    char *out = malloc(len + 1);
    if (!out) {
        return NULL;
    }
    memcpy(out, s, len + 1);
    return out;
}

static char ascii_lower(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (char)(c - 'A' + 'a');
    }
    return c;
}

static int ends_with_ci(const char *s, const char *suffix)
{
    size_t sl = strlen(s);
    size_t tl = strlen(suffix);
    if (tl > sl) {
        return 0;
    }
    s += sl - tl;
    for (size_t i = 0; i < tl; i++) {
        if (ascii_lower(s[i]) != ascii_lower(suffix[i])) {
            return 0;
        }
    }
    return 1;
}

static int is_batch_cia_input(const char *name)
{
    return ends_with_ci(name, ".cia") && !ends_with_ci(name, "-decrypted.cia");
}

void input_list_free(InputList *list)
{
    for (size_t i = 0; i < list->count; i++) {
        free(list->items[i]);
    }
    free(list->items);
    memset(list, 0, sizeof(*list));
}

int input_list_append(InputList *list, const char *path)
{
    char *copy;
    if (list->count == list->cap) {
        size_t new_cap = list->cap ? list->cap * 2 : 16;
        char **new_items = realloc(list->items, new_cap * sizeof(list->items[0]));
        if (!new_items) {
            return 0;
        }
        list->items = new_items;
        list->cap = new_cap;
    }
    copy = xstrdup(path);
    if (!copy) {
        return 0;
    }
    list->items[list->count++] = copy;
    return 1;
}

static int input_list_contains(const InputList *list, const char *path)
{
    for (size_t i = 0; i < list->count; i++) {
        if (strcmp(list->items[i], path) == 0) {
            return 1;
        }
    }
    return 0;
}

static int input_list_append_unique(InputList *list, const char *path)
{
    if (input_list_contains(list, path)) {
        return 1;
    }
    return input_list_append(list, path);
}

int append_batch_inputs(InputList *inputs)
{
    size_t before = inputs->count;

#ifdef _WIN32
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA("*.cia", &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 && is_batch_cia_input(fd.cFileName)) {
                if (!input_list_append_unique(inputs, fd.cFileName)) {
                    FindClose(h);
                    return -1;
                }
            }
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
#else
    DIR *dir = opendir(".");
    struct dirent *ent;
    if (!dir) {
        fprintf(stderr, "Failed to scan current directory: %s\n", strerror(errno));
        return -1;
    }
    while ((ent = readdir(dir)) != NULL) {
        struct stat st;
        if (!is_batch_cia_input(ent->d_name)) {
            continue;
        }
        if (stat(ent->d_name, &st) != 0 || !S_ISREG(st.st_mode)) {
            continue;
        }
        if (!input_list_append_unique(inputs, ent->d_name)) {
            closedir(dir);
            return -1;
        }
    }
    closedir(dir);
#endif

    return (int)(inputs->count - before);
}

char *join_output_path(const char *dir, const char *name)
{
    size_t dl = strlen(dir);
    size_t nl = strlen(name);
    int need_sep = dl > 0 && dir[dl - 1] != '/' && dir[dl - 1] != '\\';
    char *out = malloc(dl + (size_t)need_sep + nl + 1);
    if (!out) {
        return NULL;
    }
    memcpy(out, dir, dl);
    if (need_sep) {
        out[dl++] = PATH_SEP;
    }
    memcpy(out + dl, name, nl);
    out[dl + nl] = 0;
    return out;
}

char *make_temp_content_path(const char *dir, const char *base, uint16_t index, uint32_t id)
{
    char name[640];
    snprintf(name, sizeof(name), ".%s.%04x.%08x.tmp", base, index, id);
    return join_output_path(dir, name);
}

int content_in_cia_header(const uint8_t *cia_header, uint32_t header_size, uint16_t index)
{
    uint32_t byte_pos = CIA_CONTENT_INDEX_OFF + (uint32_t)index / 8u;
    if (header_size < CIA_CONTENT_INDEX_OFF + CIA_CONTENT_INDEX_SIZE) {
        return 1;
    }
    if (byte_pos >= header_size) {
        return 0;
    }
    return (cia_header[byte_pos] & (uint8_t)(0x80u >> (index & 7u))) != 0;
}
