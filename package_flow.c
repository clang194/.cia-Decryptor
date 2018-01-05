#include "decryptor.h"
#include "aes.h"
#include "sha256.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

static int parse_ticket(FILE *fp, uint64_t tik_off, uint32_t tik_size, const Options *opt,
                        uint8_t title_key[16], uint8_t title_id[8])
{
    uint8_t sig_buf[4];
    uint8_t enc_key[16];
    uint8_t key_id;
    int sig_size;
    uint8_t iv[16];
    uint8_t tmp[16];
    uint8_t common_key[16];

    if (tik_size < 4 || !read_exact_at(fp, tik_off, sig_buf, sizeof(sig_buf))) {
        return 0;
    }
    sig_size = sig_block_size(rd32be(sig_buf));
    if (sig_size < 0 || (uint64_t)sig_size + 0xb2u > tik_size) {
        fprintf(stderr, "Unsupported ticket signature type or truncated ticket.\n");
        return 0;
    }
    if (!read_exact_at(fp, tik_off + (uint64_t)sig_size + 0x7f, enc_key, 16) ||
        !read_exact_at(fp, tik_off + (uint64_t)sig_size + 0x9c, title_id, 8) ||
        !read_exact_at(fp, tik_off + (uint64_t)sig_size + 0xb1, &key_id, 1)) {
        return 0;
    }
    if (!load_common_key(opt, key_id, common_key)) {
        fprintf(stderr, "Unsupported common key index 0x%02x in ticket.\n", key_id);
        return 0;
    }
    memset(iv, 0, sizeof(iv));
    memcpy(iv, title_id, 8);
    memcpy(tmp, enc_key, 16);
    aes128_cbc_decrypt(common_key, iv, tmp, title_key, 16);
    return 1;
}

static void tmd_blob_free(TmdBlob *blob)
{
    if (!blob) {
        return;
    }
    free(blob->data);
    memset(blob, 0, sizeof(*blob));
}

static int parse_tmd(FILE *fp, uint64_t tmd_off, uint32_t tmd_size, const uint8_t *cia_header,
                     uint32_t cia_header_size, TmdContent **contents_out, uint16_t *count_out,
                     TmdBlob *blob_out)
{
    uint8_t *tmd;
    uint32_t sig_type;
    int sig_size;
    uint16_t count;
    uint64_t rec_off;
    TmdContent *contents;

    *contents_out = NULL;
    *count_out = 0;
    if (tmd_size < 4) {
        return 0;
    }
    tmd = malloc(tmd_size);
    if (!tmd) {
        return 0;
    }
    if (!read_exact_at(fp, tmd_off, tmd, tmd_size)) {
        free(tmd);
        return 0;
    }
    sig_type = rd32be(tmd);
    sig_size = sig_block_size(sig_type);
    if (sig_size < 0 || (uint64_t)sig_size + TMD_HEADER_SIZE > tmd_size) {
        fprintf(stderr, "Unsupported TMD signature type or truncated TMD.\n");
        free(tmd);
        return 0;
    }
    count = rd16be(tmd + sig_size + 0x9e);
    rec_off = (uint64_t)sig_size + TMD_HEADER_SIZE + TMD_INFO_RECORD_SIZE * TMD_INFO_RECORD_COUNT;
    if (rec_off + (uint64_t)count * TMD_CONTENT_RECORD_SIZE > tmd_size) {
        fprintf(stderr, "TMD content table is truncated.\n");
        free(tmd);
        return 0;
    }

    contents = calloc(count ? count : 1, sizeof(contents[0]));
    if (!contents) {
        free(tmd);
        return 0;
    }
    for (uint16_t i = 0; i < count; i++) {
        const uint8_t *rec = tmd + rec_off + (uint64_t)i * TMD_CONTENT_RECORD_SIZE;
        contents[i].id = rd32be(rec);
        contents[i].index = rd16be(rec + 4);
        contents[i].flags = rd16be(rec + 6);
        contents[i].size = rd64be(rec + 8);
        memcpy(contents[i].hash, rec + 16, 32);
        contents[i].included = content_in_cia_header(cia_header, cia_header_size, contents[i].index);
    }
    if (blob_out) {
        blob_out->data = tmd;
        blob_out->size = tmd_size;
        blob_out->sig_size = sig_size;
        blob_out->info_off = (uint64_t)sig_size + TMD_HEADER_SIZE;
        blob_out->rec_off = rec_off;
    } else {
        free(tmd);
    }
    *contents_out = contents;
    *count_out = count;
    return 1;
}

static void refresh_tmd_hashes(TmdBlob *tmd, TmdContent *contents, uint16_t count)
{
    uint8_t *info;
    uint8_t hash[32];
    int had_valid_info_record = 0;

    if (!tmd || !tmd->data) {
        return;
    }

    for (uint16_t i = 0; i < count; i++) {
        uint8_t *rec = tmd->data + tmd->rec_off + (uint64_t)i * TMD_CONTENT_RECORD_SIZE;
        if (contents[i].included) {
            uint16_t flags = (uint16_t)(contents[i].flags & ~1u);
            wr16be(rec + 6, flags);
            memcpy(rec + 16, contents[i].hash, 32);
            contents[i].flags = flags;
        }
    }

    info = tmd->data + tmd->info_off;
    for (int i = 0; i < (int)TMD_INFO_RECORD_COUNT; i++) {
        uint8_t *record = info + (uint64_t)i * TMD_INFO_RECORD_SIZE;
        uint16_t offset = rd16be(record);
        uint16_t cmd_count = rd16be(record + 2);
        if (cmd_count == 0) {
            continue;
        }
        if ((uint32_t)offset + cmd_count > count) {
            continue;
        }
        sha256_hash(tmd->data + tmd->rec_off + (uint64_t)offset * TMD_CONTENT_RECORD_SIZE,
                    (size_t)cmd_count * TMD_CONTENT_RECORD_SIZE, record + 4);
        had_valid_info_record = 1;
    }

    if (!had_valid_info_record && tmd->size >= tmd->info_off + TMD_INFO_RECORD_SIZE * TMD_INFO_RECORD_COUNT) {
        memset(info, 0, TMD_INFO_RECORD_SIZE * TMD_INFO_RECORD_COUNT);
        wr16be(info, 0);
        wr16be(info + 2, count);
        sha256_hash(tmd->data + tmd->rec_off, (size_t)count * TMD_CONTENT_RECORD_SIZE, info + 4);
    }

    sha256_hash(info, TMD_INFO_RECORD_SIZE * TMD_INFO_RECORD_COUNT, hash);
    memcpy(tmd->data + (uint64_t)tmd->sig_size + 0xa4, hash, 32);
}

static void assign_content_offsets(TmdContent *contents, uint16_t count, uint64_t content_off)
{
    uint64_t next = 0;
    for (uint16_t i = 0; i < count; i++) {
        if (!contents[i].included) {
            continue;
        }
        contents[i].cia_offset = content_off + next;
        next += align_up(contents[i].size, CIA_ALIGN);
    }
}

static void init_content_reader(ContentReader *reader, FILE *fp, uint64_t file_size,
                                const TmdContent *content, const uint8_t title_key[16])
{
    memset(reader, 0, sizeof(*reader));
    reader->fp = fp;
    reader->file_size = file_size;
    reader->base = content->cia_offset;
    reader->size = content->size;
    reader->encrypted = (content->flags & 1u) != 0;
    reader->index = content->index;
    memcpy(reader->title_key, title_key, 16);
}
static int extract_contents_to_files(const Options *opt, const SeedDb *seeddb, FILE *fp,
                                     uint64_t file_size, const char *base,
                                     TmdContent *contents, uint16_t count,
                                     const uint8_t title_key[16])
{
    int ok = 1;

    for (uint16_t i = 0; i < count; i++) {
        char out_name[640];
        char *out_path = NULL;
        ContentReader reader;
        int is_ncch;

        if (!contents[i].included) {
            continue;
        }
        init_content_reader(&reader, fp, file_size, &contents[i], title_key);
        if (reader.encrypted && (reader.size & 0xfu) != 0) {
            fprintf(stderr, "Content %04x size is not AES-block aligned; skipping.\n", reader.index);
            ok = 0;
            continue;
        }

        is_ncch = content_is_ncch(&reader);
        if (is_ncch && !opt->raw_content) {
            snprintf(out_name, sizeof(out_name), "%s.%04x.%08x.ncch", base, contents[i].index, contents[i].id);
        } else {
            snprintf(out_name, sizeof(out_name), "%s.%04x.%08x.app", base, contents[i].index, contents[i].id);
        }
        out_path = join_output_path(opt->out_dir, out_name);
        if (!out_path) {
            ok = 0;
            continue;
        }
        if (!decrypt_content_to_path(opt, seeddb, &reader, &contents[i], out_path)) {
            ok = 0;
        }
        free(out_path);
    }

    return ok;
}

static int copy_whole_file_to_path(FILE *in, const char *out_path)
{
    FILE *out = fopen(out_path, "wb");
    uint64_t size;
    int ok;

    if (!out) {
        fprintf(stderr, "Failed to create '%s': %s\n", out_path, strerror(errno));
        return 0;
    }
    size = get_file_size(in);
    ok = copy_range(in, out, 0, size);
    if (fclose(out) != 0) {
        ok = 0;
    }
    return ok;
}

static int rebuild_decrypted_cia(const Options *opt, const SeedDb *seeddb, FILE *fp,
                                 uint64_t file_size, const char *base,
                                 const uint8_t *cia_header, uint32_t header_size,
                                 uint64_t cert_off, uint32_t cert_size,
                                 uint64_t tik_off, uint32_t tik_size,
                                 uint64_t tmd_off, TmdBlob *tmd,
                                 uint64_t content_off, uint64_t content_size,
                                 uint64_t meta_off, uint32_t meta_size,
                                 TmdContent *contents, uint16_t count,
                                 const uint8_t title_key[16])
{
    char out_name[640];
    char *out_path = NULL;
    char **temp_paths = NULL;
    FILE *out = NULL;
    int ok = 1;

    snprintf(out_name, sizeof(out_name), "%s-decrypted.cia", base);
    out_path = join_output_path(opt->out_dir, out_name);
    temp_paths = calloc(count ? count : 1, sizeof(temp_paths[0]));
    if (!out_path || !temp_paths) {
        ok = 0;
        goto done;
    }

    for (uint16_t i = 0; i < count; i++) {
        ContentReader reader;
        uint64_t tmp_size = 0;

        if (!contents[i].included) {
            continue;
        }
        init_content_reader(&reader, fp, file_size, &contents[i], title_key);
        if (reader.encrypted && (reader.size & 0xfu) != 0) {
            fprintf(stderr, "Content %04x size is not AES-block aligned; skipping.\n", reader.index);
            ok = 0;
            goto done;
        }
        temp_paths[i] = make_temp_content_path(opt->out_dir, base, contents[i].index, contents[i].id);
        if (!temp_paths[i]) {
            ok = 0;
            goto done;
        }
        if (!decrypt_content_to_path(opt, seeddb, &reader, &contents[i], temp_paths[i]) ||
            !sha256_named_file(temp_paths[i], contents[i].hash, &tmp_size) ||
            tmp_size != contents[i].size) {
            fprintf(stderr, "Failed to produce decrypted content %04x.\n", contents[i].index);
            ok = 0;
            goto done;
        }
    }

    refresh_tmd_hashes(tmd, contents, count);

    out = fopen(out_path, "wb");
    if (!out) {
        fprintf(stderr, "Failed to create '%s': %s\n", out_path, strerror(errno));
        ok = 0;
        goto done;
    }

    if (!write_all(out, cia_header, header_size) ||
        !pad_to_offset(out, cert_off) ||
        !copy_range(fp, out, cert_off, cert_size) ||
        !pad_to_offset(out, tik_off) ||
        !copy_range(fp, out, tik_off, tik_size) ||
        !pad_to_offset(out, tmd_off) ||
        !write_all(out, tmd->data, tmd->size) ||
        !pad_to_offset(out, content_off)) {
        ok = 0;
        goto done;
    }

    for (uint16_t i = 0; i < count; i++) {
        if (!contents[i].included) {
            continue;
        }
        if (!copy_named_file(out, temp_paths[i]) ||
            !write_zeros(out, align_up(contents[i].size, CIA_ALIGN) - contents[i].size)) {
            ok = 0;
            goto done;
        }
    }

    if (!pad_to_offset(out, content_off + content_size) ||
        !pad_to_offset(out, meta_off) ||
        !copy_range(fp, out, meta_off, meta_size)) {
        ok = 0;
        goto done;
    }

    if (fclose(out) != 0) {
        out = NULL;
        ok = 0;
        goto done;
    }
    out = NULL;
    logv(opt, "wrote %s\n", out_path);

done:
    if (out && fclose(out) != 0) {
        ok = 0;
    }
    if (!ok && out_path) {
        remove(out_path);
    }
    if (temp_paths) {
        for (uint16_t i = 0; i < count; i++) {
            if (temp_paths[i]) {
                remove(temp_paths[i]);
                free(temp_paths[i]);
            }
        }
    }
    free(temp_paths);
    free(out_path);
    return ok;
}

int process_cia(const char *path, const Options *opt, const SeedDb *seeddb)
{
    FILE *fp;
    uint8_t first[CIA_HEADER_MIN];
    uint8_t *cia_header = NULL;
    uint32_t header_size;
    uint16_t type;
    uint16_t version;
    uint32_t cert_size, tik_size, tmd_size, meta_size;
    uint64_t content_size;
    uint64_t cert_off, tik_off, tmd_off, content_off, meta_off;
    uint64_t file_size;
    uint8_t title_key[16] = {0};
    uint8_t title_id[8] = {0};
    TmdContent *contents = NULL;
    TmdBlob tmd = {0};
    uint16_t content_count = 0;
    char *base = NULL;
    int ok = 1;

    fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open '%s': %s\n", path, strerror(errno));
        return 0;
    }
    if (!read_exact_at(fp, 0, first, sizeof(first))) {
        fprintf(stderr, "'%s' is too small to be a CIA.\n", path);
        fclose(fp);
        return 0;
    }
    header_size = rd32le(first);
    type = rd16le(first + 4);
    version = rd16le(first + 6);
    cert_size = rd32le(first + 8);
    tik_size = rd32le(first + 12);
    tmd_size = rd32le(first + 16);
    meta_size = rd32le(first + 20);
    content_size = rd64le(first + 24);

    if (header_size < CIA_HEADER_MIN || header_size > (1u << 20) || type != 0) {
        fprintf(stderr, "'%s' does not look like a normal CIA file.\n", path);
        fclose(fp);
        return 0;
    }
    cia_header = malloc(header_size);
    if (!cia_header || !read_exact_at(fp, 0, cia_header, header_size)) {
        fprintf(stderr, "Failed to read CIA header.\n");
        free(cia_header);
        fclose(fp);
        return 0;
    }

    cert_off = align_up(header_size, CIA_ALIGN);
    tik_off = align_up(cert_off + cert_size, CIA_ALIGN);
    tmd_off = align_up(tik_off + tik_size, CIA_ALIGN);
    content_off = align_up(tmd_off + tmd_size, CIA_ALIGN);
    meta_off = align_up(content_off + content_size, CIA_ALIGN);
    (void)meta_off;
    (void)meta_size;
    file_size = get_file_size(fp);
    if (content_off > file_size || content_size > file_size - content_off) {
        fprintf(stderr, "'%s' is truncated before the CIA content section ends.\n", path);
        ok = 0;
        goto done;
    }

    base = path_basename_no_ext(path);
    if (!base) {
        ok = 0;
        goto done;
    }

    if (version == 1 || tik_size == 0 || tmd_size == 0) {
        TmdContent simple;
        char out_name[512];
        char *out_path;
        ContentReader reader;
        memset(&simple, 0, sizeof(simple));
        simple.size = content_size;
        if (!opt->extract_contents) {
            snprintf(out_name, sizeof(out_name), "%s-decrypted.cia", base);
            out_path = join_output_path(opt->out_dir, out_name);
            if (!out_path) {
                ok = 0;
                goto done;
            }
            ok = copy_whole_file_to_path(fp, out_path);
            free(out_path);
            goto done;
        }

        snprintf(out_name, sizeof(out_name), "%s.simple-content.app", base);
        out_path = join_output_path(opt->out_dir, out_name);
        if (!out_path) {
            ok = 0;
            goto done;
        }
        memset(&reader, 0, sizeof(reader));
        reader.fp = fp;
        reader.file_size = get_file_size(fp);
        reader.base = content_off;
        reader.size = content_size;
        reader.encrypted = 0;
        ok = decrypt_content_blob(&reader, out_path);
        free(out_path);
        goto done;
    }

    if (!parse_ticket(fp, tik_off, tik_size, opt, title_key, title_id) ||
        !parse_tmd(fp, tmd_off, tmd_size, cia_header, header_size, &contents, &content_count, &tmd)) {
        ok = 0;
        goto done;
    }
    assign_content_offsets(contents, content_count, content_off);

    {
        char tid[17];
        hex64_be(tid, title_id);
        logv(opt, "%s: title %s, %u content record(s)\n", path, tid, content_count);
    }

    if (opt->extract_contents) {
        ok = extract_contents_to_files(opt, seeddb, fp, file_size, base, contents, content_count, title_key);
    } else {
        ok = rebuild_decrypted_cia(opt, seeddb, fp, file_size, base, cia_header, header_size,
                                   cert_off, cert_size, tik_off, tik_size, tmd_off, &tmd,
                                   content_off, content_size, meta_off, meta_size,
                                   contents, content_count, title_key);
    }

done:
    tmd_blob_free(&tmd);
    free(contents);
    free(base);
    free(cia_header);
    fclose(fp);
    return ok;
}
