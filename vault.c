#include "decryptor.h"
#include "builtin_seeddb.h"

#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t retail_common_keys[6][16] = {
    {0xc3,0x21,0xdc,0x0b,0x46,0xe2,0xcc,0xda,0xbd,0x97,0xa3,0xaa,0xd1,0x83,0x26,0xa2},
    {0xed,0x4e,0x1c,0x50,0xbc,0x0c,0xc2,0x7a,0x5f,0x7d,0xbd,0x75,0x73,0x39,0x36,0xf2},
    {0x5c,0x54,0xce,0xd2,0x40,0x68,0xcd,0xb6,0xdc,0x01,0x90,0x72,0xc0,0xb1,0x94,0x45},
    {0x82,0x71,0xba,0x24,0x4b,0x98,0x8a,0x20,0xe7,0x8d,0x91,0xfc,0xad,0x0d,0x80,0xfc},
    {0xdd,0x3e,0x03,0x94,0x64,0x1c,0x63,0x9e,0x0d,0x5b,0xa9,0x81,0x4d,0x2e,0x13,0x84},
    {0x02,0xe1,0x3d,0xff,0x28,0xa5,0xda,0x68,0x74,0x03,0x85,0x87,0x6e,0x19,0x33,0x38},
};

static const uint8_t dev_common_keys[6][16] = {
    {0xf2,0x47,0xd9,0x2c,0x26,0x10,0x19,0x07,0xd5,0xa9,0x4a,0xc7,0x90,0x5e,0xe8,0x01},
    {0xe3,0xd0,0xcc,0x4a,0x19,0xd4,0xb4,0xb9,0x24,0x4e,0xc8,0x28,0xf8,0x2f,0xf1,0x1f},
    {0x51,0xca,0x1e,0xcb,0x15,0xf0,0xb7,0x4d,0xa7,0x52,0xe5,0x37,0x2b,0xa6,0xd4,0xe6},
    {0x8c,0xad,0xea,0x31,0x02,0x40,0xcc,0xff,0x1b,0x3e,0xe4,0xa1,0x36,0x1a,0xc3,0x1d},
    {0xd2,0xe1,0x73,0xe1,0x31,0xc4,0x11,0x55,0xda,0x04,0xdc,0xdc,0xd6,0x39,0x50,0x25},
    {0x0d,0x3e,0x6d,0xf6,0x6d,0x3d,0xbc,0x25,0x6f,0x6c,0xf0,0xa2,0xf5,0x0f,0xf0,0x59},
};

static const uint8_t retail_ncch_keyx[4][16] = {
    {0x1e,0x6a,0xb4,0x90,0x51,0xe6,0x58,0x45,0x90,0xba,0xa0,0x0b,0x6a,0xf4,0x3d,0x69},
    {0x69,0x03,0xf9,0xf5,0xab,0x18,0x18,0xfc,0x0a,0xc2,0xfc,0xa5,0x01,0x6c,0xa7,0xc9},
    {0x25,0x0d,0xe8,0xe0,0x24,0x60,0xa8,0xea,0xfa,0x20,0xc9,0xe6,0xfe,0x87,0xbe,0x4e},
    {0xe2,0x49,0x25,0xcb,0xa2,0x4a,0xd2,0x9a,0x1c,0xbe,0x43,0xdc,0xf8,0x0e,0x9c,0xb8},
};

static const uint8_t dev_ncch_keyx[4][16] = {
    {0xf6,0xe6,0x26,0x0f,0xce,0xdf,0xde,0xe3,0x01,0xe8,0x34,0x8d,0x06,0x22,0xc7,0x27},
    {0x26,0x74,0x5b,0x15,0xf4,0xc3,0x52,0x60,0xb5,0xab,0x70,0x32,0x4d,0x8a,0x2a,0x21},
    {0x97,0xaf,0xd0,0x18,0x18,0xaa,0xfb,0x36,0x9e,0x92,0xb4,0x06,0x10,0x18,0xbf,0x4c},
    {0xcb,0x6f,0x08,0x1a,0x3b,0xaa,0x75,0x67,0x76,0x8d,0xd6,0x86,0x9b,0x92,0xb2,0x8c},
};

static const uint8_t fixed_app_key[16] = {
    0xa7,0xe4,0x21,0x5e,0x9b,0xd8,0x15,0x52,0x8f,0xcc,0x09,0x46,0x83,0xc0,0xfd,0x3a
};

static const uint8_t fixed_system_key[16] = {
    0xf5,0x98,0xc7,0x6e,0x32,0x12,0x25,0x0d,0xb9,0x5a,0xfa,0x8b,0x6a,0x94,0xe4,0x71
};

static uint8_t xor_mask(size_t pos)
{
    return (uint8_t)(0xa7u + pos * 0x3du + pos / 16u);
}

static uint8_t xor_decode_byte(uint8_t value, size_t pos)
{
    return (uint8_t)(value ^ xor_mask(pos));
}

static void xor_decode_key16(const uint8_t in[16], uint8_t out[16])
{
    for (size_t i = 0; i < 16; i++) {
        out[i] = xor_decode_byte(in[i], i);
    }
}

int load_common_key(const Options *opt, uint8_t key_id, uint8_t out[16])
{
    if (key_id >= 6) {
        return 0;
    }
    xor_decode_key16(opt->devkeys ? dev_common_keys[key_id] : retail_common_keys[key_id], out);
    return 1;
}
static int keyx_slot(uint8_t security_version)
{
    switch (security_version) {
        case 0x00: return 0;
        case 0x01: return 1;
        case 0x0a: return 2;
        case 0x0b: return 3;
        default: return -1;
    }
}

int load_ncch_keyx(const Options *opt, uint8_t security_version, uint8_t out[16])
{
    int slot = keyx_slot(security_version);
    if (slot < 0) {
        return 0;
    }
    xor_decode_key16(opt->devkeys ? dev_ncch_keyx[slot] : retail_ncch_keyx[slot], out);
    return 1;
}

static int bit_get_be(const uint8_t in[16], int bit)
{
    return (in[bit / 8] >> (7 - (bit & 7))) & 1;
}

static void bit_set_be(uint8_t out[16], int bit)
{
    out[bit / 8] |= (uint8_t)(1u << (7 - (bit & 7)));
}

static void rol128(const uint8_t in[16], unsigned bits, uint8_t out[16])
{
    memset(out, 0, 16);
    bits %= 128;
    for (int src = 0; src < 128; src++) {
        if (bit_get_be(in, src)) {
            int dst = (src - (int)bits) & 127;
            bit_set_be(out, dst);
        }
    }
}

static void add128_be(const uint8_t a[16], const uint8_t b[16], uint8_t out[16])
{
    unsigned carry = 0;
    for (int i = 15; i >= 0; i--) {
        unsigned sum = (unsigned)a[i] + b[i] + carry;
        out[i] = (uint8_t)sum;
        carry = sum >> 8;
    }
}

void scramble_key(const uint8_t keyx[16], const uint8_t keyy[16], uint8_t out[16])
{
    static const uint8_t add_const[16] = {
        0x1f,0xf9,0xe9,0xaa,0xc5,0xfe,0x04,0x08,0x02,0x45,0x91,0xdc,0x5d,0x52,0x76,0x8a
    };
    uint8_t tmp[16];
    uint8_t sum[16];

    rol128(keyx, 2, tmp);
    for (int i = 0; i < 16; i++) {
        tmp[i] ^= keyy[i];
    }
    add128_be(tmp, add_const, sum);
    rol128(sum, 87, out);
}

static int scramble_self_test(void)
{
    static const uint8_t keyy[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const uint8_t expected[16] = {
        0x8c,0x83,0x18,0x42,0xe5,0x83,0x1a,0x9f,0x71,0x79,0x7d,0x1b,0x31,0xbc,0x0c,0xa0
    };
    uint8_t out[16];
    uint8_t keyx[16];
    xor_decode_key16(retail_ncch_keyx[0], keyx);
    scramble_key(keyx, keyy, out);
    return memcmp(out, expected, sizeof(expected)) == 0;
}

static int builtin_seeddb_self_test(void)
{
    uint8_t hdr[4];
    if (builtin_seeddb_xor_len != 59568u) {
        return 0;
    }
    for (size_t i = 0; i < sizeof(hdr); i++) {
        hdr[i] = xor_decode_byte(builtin_seeddb_xor[i], i);
    }
    return rd32le(hdr) == 0x745u;
}
int seeddb_load(SeedDb *db, const Options *opt)
{
    FILE *fp;
    uint8_t hdr[16];
    uint32_t count;

    memset(db, 0, sizeof(*db));
    if (opt->fallback_seed_hex) {
        if (!hex_to_bytes(opt->fallback_seed_hex, db->fallback_seed, sizeof(db->fallback_seed))) {
            fprintf(stderr, "Invalid --seed value; expected 32 hex characters.\n");
            return 0;
        }
        db->has_fallback_seed = 1;
    }
    if (!opt->seeddb_path) {
        uint8_t hdr_dec[16];
        if (builtin_seeddb_xor_len < 16) {
            fprintf(stderr, "Built-in seeddb is invalid.\n");
            return 0;
        }
        for (size_t i = 0; i < sizeof(hdr_dec); i++) {
            hdr_dec[i] = xor_decode_byte(builtin_seeddb_xor[i], i);
        }
        count = rd32le(hdr_dec);
        if (builtin_seeddb_xor_len < 16u + count * 32u) {
            fprintf(stderr, "Built-in seeddb is truncated.\n");
            return 0;
        }
        db->entries = calloc(count ? count : 1, sizeof(db->entries[0]));
        if (!db->entries) {
            return 0;
        }
        db->count = count;
        for (uint32_t i = 0; i < count; i++) {
            uint8_t entry[32];
            size_t entry_pos = 16u + (size_t)i * 32u;
            for (size_t j = 0; j < sizeof(entry); j++) {
                entry[j] = xor_decode_byte(builtin_seeddb_xor[entry_pos + j], entry_pos + j);
            }
            db->entries[i].title_id = rd64le(entry);
            memcpy(db->entries[i].seed, entry + 8, 16);
        }
        logv(opt, "Loaded %zu built-in seeddb entries.\n", db->count);
        return 1;
    }

    fp = fopen(opt->seeddb_path, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open seeddb '%s': %s\n", opt->seeddb_path, strerror(errno));
        return 0;
    }
    if (!read_exact_at(fp, 0, hdr, sizeof(hdr))) {
        fprintf(stderr, "Failed to read seeddb header.\n");
        fclose(fp);
        return 0;
    }
    count = rd32le(hdr);
    db->entries = calloc(count ? count : 1, sizeof(db->entries[0]));
    if (!db->entries) {
        fclose(fp);
        return 0;
    }
    db->count = count;
    for (uint32_t i = 0; i < count; i++) {
        uint8_t entry[32];
        if (!read_exact_at(fp, 16ull + (uint64_t)i * 32u, entry, sizeof(entry))) {
            fprintf(stderr, "Seeddb ended early at entry %" PRIu32 ".\n", i);
            fclose(fp);
            return 0;
        }
        db->entries[i].title_id = rd64le(entry);
        memcpy(db->entries[i].seed, entry + 8, 16);
    }
    fclose(fp);
    logv(opt, "Loaded %zu seeddb entries.\n", db->count);
    return 1;
}

void seeddb_free(SeedDb *db)
{
    free(db->entries);
    memset(db, 0, sizeof(*db));
}

const uint8_t *seeddb_find(const SeedDb *db, uint64_t title_id)
{
    if (db->has_fallback_seed) {
        return db->fallback_seed;
    }
    for (size_t i = 0; i < db->count; i++) {
        if (db->entries[i].title_id == title_id) {
            return db->entries[i].seed;
        }
    }
    return NULL;
}

void load_fixed_ncch_key(const uint8_t title_id[8], uint8_t out[16])
{
    xor_decode_key16((title_id[3] & 0x10u) ? fixed_system_key : fixed_app_key, out);
}

int vault_self_test(void)
{
    return scramble_self_test() && builtin_seeddb_self_test();
}
