#include "decryptor.h"
#include "aes.h"
#include "sha256.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t raw[NCCH_HEADER_SIZE];
    uint8_t title_id[8];
    uint8_t program_id[8];
    uint8_t seed_checksum[4];
    uint8_t flags[8];
    uint8_t product_code[17];
    uint32_t ncch_size;
    uint32_t exhdr_size;
    uint32_t plain_off;
    uint32_t plain_size;
    uint32_t logo_off;
    uint32_t logo_size;
    uint32_t exefs_off;
    uint32_t exefs_size;
    uint32_t romfs_off;
    uint32_t romfs_size;
    uint8_t format_version;
    uint8_t security_version;
    uint64_t block_size;
    uint64_t program_id_le;
} NcchHeader;

typedef struct {
    uint64_t off;
    uint64_t end;
} Range;

int content_reader_read_at(const ContentReader *r, uint64_t off, uint8_t *out, size_t len)
{
    uint8_t iv[16];

    if (off > r->size || len > r->size - off) {
        return 0;
    }
    if (r->base > r->file_size || off > r->file_size - r->base ||
        len > r->file_size - r->base - off) {
        return 0;
    }
    if (!r->encrypted) {
        return read_exact_at(r->fp, r->base + off, out, len);
    }
    if ((off & 0xfu) != 0 || (len & 0xfu) != 0) {
        return 0;
    }
    if (off == 0) {
        memset(iv, 0, sizeof(iv));
        iv[0] = (uint8_t)(r->index >> 8);
        iv[1] = (uint8_t)r->index;
    } else if (!read_exact_at(r->fp, r->base + off - 16, iv, sizeof(iv))) {
        return 0;
    }
    if (!read_exact_at(r->fp, r->base + off, out, len)) {
        return 0;
    }
    aes128_cbc_decrypt(r->title_key, iv, out, out, len);
    return 1;
}

static int copy_cia_level_region(FILE *out, const ContentReader *r, uint64_t off, uint64_t size)
{
    uint8_t *buf = malloc(COPY_CHUNK);
    uint64_t pos = 0;
    int ok = 1;

    if (!buf) {
        return 0;
    }
    while (pos < size) {
        size_t chunk = (size - pos) > COPY_CHUNK ? COPY_CHUNK : (size_t)(size - pos);
        if (r->encrypted && (chunk & 0xfu)) {
            chunk &= ~(size_t)0xfu;
            if (chunk == 0) {
                ok = 0;
                break;
            }
        }
        if (!content_reader_read_at(r, off + pos, buf, chunk) || !write_all(out, buf, chunk)) {
            ok = 0;
            break;
        }
        pos += chunk;
    }
    free(buf);
    return ok && pos == size;
}
static int parse_ncch_header(const uint8_t raw[NCCH_HEADER_SIZE], NcchHeader *h)
{
    memset(h, 0, sizeof(*h));
    if (memcmp(raw + 0x100, "NCCH", 4) != 0) {
        return 0;
    }
    memcpy(h->raw, raw, NCCH_HEADER_SIZE);
    h->ncch_size = rd32le(raw + 0x104);
    memcpy(h->title_id, raw + 0x108, 8);
    h->format_version = raw[0x112];
    memcpy(h->seed_checksum, raw + 0x114, 4);
    memcpy(h->program_id, raw + 0x118, 8);
    h->program_id_le = rd64le(raw + 0x118);
    memcpy(h->product_code, raw + 0x150, 16);
    h->product_code[16] = 0;
    h->exhdr_size = rd32le(raw + 0x180);
    memcpy(h->flags, raw + 0x188, 8);
    h->security_version = h->flags[3];
    h->plain_off = rd32le(raw + 0x190);
    h->plain_size = rd32le(raw + 0x194);
    h->logo_off = rd32le(raw + 0x198);
    h->logo_size = rd32le(raw + 0x19c);
    h->exefs_off = rd32le(raw + 0x1a0);
    h->exefs_size = rd32le(raw + 0x1a4);
    h->romfs_off = rd32le(raw + 0x1b0);
    h->romfs_size = rd32le(raw + 0x1b4);
    if (h->format_version == 1) {
        h->block_size = 1;
    } else if (h->flags[6] < 20) {
        h->block_size = 1ull << (h->flags[6] + 9);
    } else {
        h->block_size = NCCH_MEDIA_UNIT;
    }
    return 1;
}

static uint64_t ncch_blk_to_off(const NcchHeader *h, uint32_t blk)
{
    return (uint64_t)blk * h->block_size;
}

static void ncch_counter(const NcchHeader *h, int section_type, uint64_t section_off, uint8_t ctr[16])
{
    memset(ctr, 0, 16);
    if (h->format_version == 0 || h->format_version == 2) {
        for (int i = 0; i < 8; i++) {
            ctr[i] = h->title_id[7 - i];
        }
        ctr[8] = (uint8_t)section_type;
    } else {
        memcpy(ctr, h->title_id, 8);
        ctr[12] = (uint8_t)(section_off >> 24);
        ctr[13] = (uint8_t)(section_off >> 16);
        ctr[14] = (uint8_t)(section_off >> 8);
        ctr[15] = (uint8_t)section_off;
    }
}

static uint64_t ncch_exheader_region_size(const NcchHeader *h)
{
    if (h->exhdr_size == 0) {
        if (h->format_version == 1 && h->raw[0x160] != 0) {
            return 0x800;
        }
        return 0;
    }
    if (h->format_version == 1 && h->exhdr_size == 0x800) {
        return 0x800;
    }
    return (uint64_t)h->exhdr_size + EXHEADER_ACCESS_DESC_SIZE;
}

static int ncch_is_crypto_stripped(const ContentReader *r, const NcchHeader *h)
{
    uint64_t size = h->exhdr_size;
    uint8_t hash[32];
    uint8_t *buf;
    int same;

    if (size == 0 || size > 0x100000) {
        return 0;
    }
    buf = malloc((size_t)size);
    if (!buf) {
        return 0;
    }
    if (!content_reader_read_at(r, NCCH_HEADER_SIZE, buf, (size_t)size)) {
        free(buf);
        return 0;
    }
    sha256_hash(buf, (size_t)size, hash);
    same = memcmp(hash, h->raw + 0x160, 32) == 0;
    free(buf);
    return same;
}

static int derive_ncch_keys(const Options *opt, const SeedDb *seeddb, const ContentReader *r,
                            const NcchHeader *h, uint8_t key0[16], uint8_t key1[16],
                            int *ncch_encrypted)
{
    uint8_t keyy0[16];
    uint8_t keyy1[16];
    uint8_t keyx0[16];
    uint8_t keyx1[16];
    const uint8_t *seed;

    *ncch_encrypted = (h->flags[7] & 0x04u) == 0;
    if (*ncch_encrypted && ncch_is_crypto_stripped(r, h)) {
        *ncch_encrypted = 0;
    }
    if (!*ncch_encrypted) {
        memset(key0, 0, 16);
        memset(key1, 0, 16);
        return 1;
    }

    if (h->flags[7] & 0x01u) {
        load_fixed_ncch_key(h->title_id, key0);
        memcpy(key1, key0, 16);
        return 1;
    }

    if (!load_ncch_keyx(opt, 0, keyx0) || !load_ncch_keyx(opt, h->security_version, keyx1)) {
        fprintf(stderr, "Unsupported NCCH security version 0x%02x.\n", h->security_version);
        return 0;
    }

    memcpy(keyy0, h->raw, 16);
    memcpy(keyy1, keyy0, 16);

    if (h->flags[7] & 0x20u) {
        uint8_t hash[32];
        seed = seeddb_find(seeddb, h->program_id_le);
        if (!seed) {
            char tid[17];
            uint8_t prog_be[8];
            for (int i = 0; i < 8; i++) {
                prog_be[i] = h->program_id[7 - i];
            }
            hex64_be(tid, prog_be);
            fprintf(stderr, "NCCH uses seed crypto, but no seed was found for title %s.\n", tid);
            return 0;
        }

        sha256_ctx ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, seed, 16);
        sha256_update(&ctx, h->program_id, 8);
        sha256_final(&ctx, hash);
        if (memcmp(hash, h->seed_checksum, 4) != 0) {
            fprintf(stderr, "Seed check mismatch for NCCH content.\n");
            return 0;
        }

        sha256_init(&ctx);
        sha256_update(&ctx, keyy0, 16);
        sha256_update(&ctx, seed, 16);
        sha256_final(&ctx, hash);
        memcpy(keyy1, hash, 16);
    }

    scramble_key(keyx0, keyy0, key0);
    scramble_key(keyx1, keyy1, key1);
    return 1;
}

static int copy_plain_gap(FILE *out, const ContentReader *r, uint64_t *written, uint64_t target)
{
    if (target < *written) {
        return 1;
    }
    if (target == *written) {
        return 1;
    }
    if (!copy_cia_level_region(out, r, *written, target - *written)) {
        return 0;
    }
    *written = target;
    return 1;
}

static int copy_ctr_region(FILE *out, const ContentReader *r, uint64_t off, uint64_t size,
                           const uint8_t key[16], const uint8_t ctr0[16], int encrypted)
{
    uint8_t *buf = malloc(COPY_CHUNK);
    uint8_t ctr[16];
    uint64_t pos = 0;
    int ok = 1;

    if (!buf) {
        return 0;
    }
    memcpy(ctr, ctr0, 16);
    while (pos < size) {
        size_t chunk = (size - pos) > COPY_CHUNK ? COPY_CHUNK : (size_t)(size - pos);
        if (!content_reader_read_at(r, off + pos, buf, chunk)) {
            ok = 0;
            break;
        }
        if (encrypted) {
            aes128_ctr_xcrypt(key, ctr, buf, buf, chunk);
        }
        if (!write_all(out, buf, chunk)) {
            ok = 0;
            break;
        }
        pos += chunk;
    }
    free(buf);
    return ok;
}

static int range_contains(const Range *ranges, size_t n, uint64_t pos, uint64_t *next)
{
    int inside = 0;
    uint64_t boundary = UINT64_MAX;

    for (size_t i = 0; i < n; i++) {
        if (pos >= ranges[i].off && pos < ranges[i].end) {
            inside = 1;
            if (ranges[i].end < boundary) {
                boundary = ranges[i].end;
            }
        } else if (pos < ranges[i].off && ranges[i].off < boundary) {
            boundary = ranges[i].off;
        }
    }
    *next = boundary;
    return inside;
}

static int copy_exefs_region(FILE *out, const ContentReader *r, const NcchHeader *h, uint64_t off,
                             uint64_t size, const uint8_t key0[16], const uint8_t key1[16],
                             const uint8_t ctr0[16], int encrypted)
{
    uint8_t header_raw[NCCH_HEADER_SIZE];
    uint8_t header_dec[NCCH_HEADER_SIZE];
    uint8_t *buf = NULL;
    Range ranges[10];
    size_t range_count = 0;
    uint64_t pos = 0;
    int mixed = encrypted && memcmp(key0, key1, 16) != 0;
    int ok = 1;

    if (!mixed || size < NCCH_HEADER_SIZE) {
        return copy_ctr_region(out, r, off, size, key0, ctr0, encrypted);
    }

    if (!content_reader_read_at(r, off, header_raw, sizeof(header_raw))) {
        return 0;
    }
    memcpy(header_dec, header_raw, sizeof(header_dec));
    {
        uint8_t ctr[16];
        memcpy(ctr, ctr0, 16);
        aes128_ctr_xcrypt(key0, ctr, header_dec, header_dec, sizeof(header_dec));
    }

    for (int i = 0; i < 10; i++) {
        const uint8_t *entry = header_dec + i * 0x10;
        char name[9];
        uint32_t file_off;
        uint32_t file_size;
        if (entry[0] == 0) {
            continue;
        }
        memcpy(name, entry, 8);
        name[8] = 0;
        file_off = rd32le(entry + 8) + NCCH_HEADER_SIZE;
        file_size = rd32le(entry + 12);
        if (file_size == 0 || file_off >= size) {
            continue;
        }
        if (strncmp(name, "icon", 4) == 0 || strncmp(name, "banner", 6) == 0) {
            continue;
        }
        ranges[range_count].off = file_off;
        ranges[range_count].end = align_up((uint64_t)file_off + file_size, NCCH_MEDIA_UNIT);
        if (ranges[range_count].end > size) {
            ranges[range_count].end = size;
        }
        range_count++;
    }

    buf = malloc(COPY_CHUNK);
    if (!buf) {
        return 0;
    }
    while (pos < size) {
        uint64_t boundary;
        int use_new = range_contains(ranges, range_count, pos, &boundary);
        uint64_t limit = boundary == UINT64_MAX ? size : boundary;
        size_t chunk = (size - pos) > COPY_CHUNK ? COPY_CHUNK : (size_t)(size - pos);
        if (pos + chunk > limit) {
            chunk = (size_t)(limit - pos);
        }
        if (chunk == 0) {
            ok = 0;
            break;
        }
        if (!content_reader_read_at(r, off + pos, buf, chunk)) {
            ok = 0;
            break;
        }
        if (encrypted) {
            uint8_t ctr[16];
            memcpy(ctr, ctr0, 16);
            aes128_ctr_advance(ctr, pos / 16);
            aes128_ctr_xcrypt(use_new ? key1 : key0, ctr, buf, buf, chunk);
        }
        if (!write_all(out, buf, chunk)) {
            ok = 0;
            break;
        }
        pos += chunk;
    }

    free(buf);
    (void)h;
    return ok;
}

static int decrypt_ncch_to_file(const Options *opt, const SeedDb *seeddb, const ContentReader *r,
                                const TmdContent *content, const char *out_path)
{
    uint8_t raw_hdr[NCCH_HEADER_SIZE];
    uint8_t key0[16], key1[16];
    uint8_t ctr[16];
    NcchHeader h;
    FILE *out;
    uint64_t written = 0;
    int encrypted = 0;

    if (!content_reader_read_at(r, 0, raw_hdr, sizeof(raw_hdr)) || !parse_ncch_header(raw_hdr, &h)) {
        return 0;
    }
    if (!derive_ncch_keys(opt, seeddb, r, &h, key0, key1, &encrypted)) {
        return -1;
    }

    out = fopen(out_path, "wb");
    if (!out) {
        fprintf(stderr, "Failed to create '%s': %s\n", out_path, strerror(errno));
        return -1;
    }

    h.raw[0x188 + 7] = (uint8_t)((h.raw[0x188 + 7] & 0x02u) | 0x04u);
    if (!write_all(out, h.raw, NCCH_HEADER_SIZE)) {
        fclose(out);
        return -1;
    }
    written = NCCH_HEADER_SIZE;

    if (ncch_exheader_region_size(&h)) {
        uint64_t off = NCCH_HEADER_SIZE;
        uint64_t size = ncch_exheader_region_size(&h);
        if (!copy_plain_gap(out, r, &written, off)) {
            fclose(out);
            return -1;
        }
        ncch_counter(&h, 1, off, ctr);
        if (!copy_ctr_region(out, r, off, size, key0, ctr, encrypted)) {
            fclose(out);
            return -1;
        }
        written += size;
    }

    if (h.exefs_size) {
        uint64_t off = ncch_blk_to_off(&h, h.exefs_off);
        uint64_t size = ncch_blk_to_off(&h, h.exefs_size);
        if (!copy_plain_gap(out, r, &written, off)) {
            fclose(out);
            return -1;
        }
        ncch_counter(&h, 2, off, ctr);
        if (!copy_exefs_region(out, r, &h, off, size, key0, key1, ctr, encrypted)) {
            fclose(out);
            return -1;
        }
        written += size;
    }

    if (h.romfs_size) {
        uint64_t off = ncch_blk_to_off(&h, h.romfs_off);
        uint64_t size = ncch_blk_to_off(&h, h.romfs_size);
        if (!copy_plain_gap(out, r, &written, off)) {
            fclose(out);
            return -1;
        }
        ncch_counter(&h, 3, off, ctr);
        if (!copy_ctr_region(out, r, off, size, key1, ctr, encrypted)) {
            fclose(out);
            return -1;
        }
        written += size;
    }

    if (written < content->size) {
        if (!copy_plain_gap(out, r, &written, content->size)) {
            fclose(out);
            return -1;
        }
    }

    if (fclose(out) != 0) {
        return -1;
    }
    logv(opt, "  wrote %s (%s NCCH)\n", out_path, encrypted ? "decrypted" : "already plain");
    return 1;
}

int decrypt_content_blob(const ContentReader *r, const char *out_path)
{
    FILE *out = fopen(out_path, "wb");
    int ok;
    if (!out) {
        fprintf(stderr, "Failed to create '%s': %s\n", out_path, strerror(errno));
        return 0;
    }
    ok = copy_cia_level_region(out, r, 0, r->size);
    if (fclose(out) != 0) {
        ok = 0;
    }
    return ok;
}

int decrypt_content_to_path(const Options *opt, const SeedDb *seeddb, const ContentReader *reader,
                                   const TmdContent *content, const char *out_path)
{
    uint8_t test_hdr[NCCH_HEADER_SIZE];
    int is_ncch = content_reader_read_at(reader, 0, test_hdr, sizeof(test_hdr)) &&
                  memcmp(test_hdr + 0x100, "NCCH", 4) == 0;

    if (is_ncch && !opt->raw_content) {
        int result = decrypt_ncch_to_file(opt, seeddb, reader, content, out_path);
        if (result < 0) {
            return 0;
        }
        if (result > 0) {
            return 1;
        }
    }

    if (!decrypt_content_blob(reader, out_path)) {
        return 0;
    }
    logv(opt, "  wrote %s\n", out_path);
    return 1;
}
int content_is_ncch(const ContentReader *reader)
{
    uint8_t test_hdr[NCCH_HEADER_SIZE];
    return content_reader_read_at(reader, 0, test_hdr, sizeof(test_hdr)) &&
           memcmp(test_hdr + 0x100, "NCCH", 4) == 0;
}
