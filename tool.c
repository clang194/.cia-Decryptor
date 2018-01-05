#include "decryptor.h"
#include "aes.h"
#include "sha256.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static void usage(FILE *fp)
{
    fprintf(fp,
        "Usage: cia-decrypt [options] [file.cia ...]\n"
        "\n"
        "With no input files, cia-decrypt batch-decrypts every .cia in the current directory.\n"
        "\n"
        "Options:\n"
        "  -o, --out-dir DIR   Write outputs to DIR (default: decrypted)\n"
        "  --batch             Decrypt every .cia in the current directory\n"
        "  --seeddb FILE       Replace the built-in seeddb.bin for 9.6 NCCH seed crypto\n"
        "  --seed HEX          Override seeddb with one 16-byte seed for seed crypto\n"
        "  --devkeys           Use development common/NCCH keys\n"
        "  --extract           Extract decrypted contents instead of rebuilding a CIA\n"
        "  --raw-content       With --extract, stop after CIA content AES-CBC and write .app files\n"
        "  -v, --verbose       Print per-content progress\n"
        "  --self-test         Run AES/SHA-256 known-answer tests\n"
        "  -h, --help          Show this help\n");
}

int main(int argc, char **argv)
{
    Options opt;
    SeedDb seeddb;
    InputList inputs = {0};
    int status = 0;

    memset(&opt, 0, sizeof(opt));
    opt.out_dir = "decrypted";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--self-test") == 0) {
            int ok = aes_self_test() && sha256_self_test() && vault_self_test();
            printf("%s\n", ok ? "self-test ok" : "self-test failed");
            input_list_free(&inputs);
            return ok ? 0 : 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(stdout);
            input_list_free(&inputs);
            return 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            opt.verbose = 1;
        } else if (strcmp(argv[i], "--batch") == 0) {
            opt.batch_mode = 1;
        } else if (strcmp(argv[i], "--devkeys") == 0) {
            opt.devkeys = 1;
        } else if (strcmp(argv[i], "--extract") == 0) {
            opt.extract_contents = 1;
        } else if (strcmp(argv[i], "--raw-content") == 0) {
            opt.raw_content = 1;
            opt.extract_contents = 1;
        } else if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--out-dir") == 0) && i + 1 < argc) {
            opt.out_dir = argv[++i];
        } else if (strcmp(argv[i], "--seeddb") == 0 && i + 1 < argc) {
            opt.seeddb_path = argv[++i];
        } else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            opt.fallback_seed_hex = argv[++i];
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(stderr);
            input_list_free(&inputs);
            return 1;
        } else {
            if (!input_list_append(&inputs, argv[i])) {
                input_list_free(&inputs);
                return 1;
            }
        }
    }

    if (opt.batch_mode || inputs.count == 0) {
        int found = append_batch_inputs(&inputs);
        if (found < 0) {
            input_list_free(&inputs);
            return 1;
        }
        if (found == 0 && inputs.count == 0) {
            fprintf(stderr, "No CIA files found in the current directory.\n");
            input_list_free(&inputs);
            return 1;
        }
    }

    if (!mkdir_p(opt.out_dir)) {
        fprintf(stderr, "Failed to create output directory '%s': %s\n", opt.out_dir, strerror(errno));
        input_list_free(&inputs);
        return 1;
    }
    if (!seeddb_load(&seeddb, &opt)) {
        input_list_free(&inputs);
        return 1;
    }

    for (size_t i = 0; i < inputs.count; i++) {
        if (!process_cia(inputs.items[i], &opt, &seeddb)) {
            status = 1;
        }
    }

    seeddb_free(&seeddb);
    input_list_free(&inputs);
    return status;
}
