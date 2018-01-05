#ifndef DECRYPTOR_H
#define DECRYPTOR_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define CIA_ALIGN 0x40u
#define CIA_HEADER_MIN 0x20u
#define CIA_CONTENT_INDEX_OFF 0x20u
#define CIA_CONTENT_INDEX_SIZE 0x2000u
#define NCCH_HEADER_SIZE 0x200u
#define NCCH_MEDIA_UNIT 0x200u
#define EXHEADER_ACCESS_DESC_SIZE 0x400u
#define TMD_HEADER_SIZE 0xC4u
#define TMD_INFO_RECORD_SIZE 0x24u
#define TMD_INFO_RECORD_COUNT 64u
#define TMD_CONTENT_RECORD_SIZE 0x30u
#define COPY_CHUNK 0x10000u

typedef struct {
    const char *out_dir;
    const char *seeddb_path;
    const char *fallback_seed_hex;
    int verbose;
    int devkeys;
    int extract_contents;
    int raw_content;
    int batch_mode;
} Options;

typedef struct {
    char **items;
    size_t count;
    size_t cap;
} InputList;

typedef struct {
    uint64_t title_id;
    uint8_t seed[16];
} SeedEntry;

typedef struct {
    SeedEntry *entries;
    size_t count;
    uint8_t fallback_seed[16];
    int has_fallback_seed;
} SeedDb;

typedef struct {
    FILE *fp;
    uint64_t file_size;
    uint64_t base;
    uint64_t size;
    int encrypted;
    uint16_t index;
    uint8_t title_key[16];
} ContentReader;

typedef struct {
    uint32_t id;
    uint16_t index;
    uint16_t flags;
    uint64_t size;
    uint8_t hash[32];
    int included;
    uint64_t cia_offset;
} TmdContent;

typedef struct {
    uint8_t *data;
    uint32_t size;
    int sig_size;
    uint64_t info_off;
    uint64_t rec_off;
} TmdBlob;

void logv(const Options *opt, const char *fmt, ...);
uint16_t rd16be(const uint8_t *p);
uint16_t rd16le(const uint8_t *p);
uint32_t rd32be(const uint8_t *p);
uint32_t rd32le(const uint8_t *p);
uint64_t rd64be(const uint8_t *p);
uint64_t rd64le(const uint8_t *p);
void wr16be(uint8_t *p, uint16_t v);
uint64_t align_up(uint64_t value, uint64_t alignment);
int read_exact_at(FILE *fp, uint64_t off, void *buf, size_t len);
int write_all(FILE *fp, const void *buf, size_t len);
int write_zeros(FILE *fp, uint64_t len);
int pad_to_offset(FILE *fp, uint64_t target);
uint64_t get_file_size(FILE *fp);
int copy_range(FILE *in, FILE *out, uint64_t off, uint64_t size);
int copy_named_file(FILE *out, const char *path);
int sha256_named_file(const char *path, uint8_t hash[32], uint64_t *size_out);
int sig_block_size(uint32_t sig_type);
int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len);
void hex64_be(char out[17], const uint8_t in[8]);
int mkdir_p(const char *path);
char *path_basename_no_ext(const char *path);
void input_list_free(InputList *list);
int input_list_append(InputList *list, const char *path);
int append_batch_inputs(InputList *inputs);
char *join_output_path(const char *dir, const char *name);
char *make_temp_content_path(const char *dir, const char *base, uint16_t index, uint32_t id);
int content_in_cia_header(const uint8_t *cia_header, uint32_t header_size, uint16_t index);

int load_common_key(const Options *opt, uint8_t key_id, uint8_t out[16]);
int load_ncch_keyx(const Options *opt, uint8_t security_version, uint8_t out[16]);
void load_fixed_ncch_key(const uint8_t title_id[8], uint8_t out[16]);
void scramble_key(const uint8_t keyx[16], const uint8_t keyy[16], uint8_t out[16]);
int vault_self_test(void);
int seeddb_load(SeedDb *db, const Options *opt);
void seeddb_free(SeedDb *db);
const uint8_t *seeddb_find(const SeedDb *db, uint64_t title_id);

int content_reader_read_at(const ContentReader *r, uint64_t off, uint8_t *out, size_t len);
int content_is_ncch(const ContentReader *reader);
int decrypt_content_blob(const ContentReader *r, const char *out_path);
int decrypt_content_to_path(const Options *opt, const SeedDb *seeddb, const ContentReader *reader,
                            const TmdContent *content, const char *out_path);

int process_cia(const char *path, const Options *opt, const SeedDb *seeddb);

#endif
