// Generic defensive IOCTL reachability harness.
// It opens an authorized lab device and sends zero-filled buffers for codes
// listed in ioctl.json. It does not contain exploit payloads.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_hex(const char *text, DWORD *out) {
    while (*text && !(isxdigit((unsigned char)*text))) {
        text++;
    }
    if (!_strnicmp(text, "0x", 2)) {
        text += 2;
    }
    char *end = NULL;
    unsigned long value = strtoul(text, &end, 16);
    if (end == text) {
        return 0;
    }
    *out = (DWORD)value;
    return 1;
}

static char *read_file(const char *path) {
    FILE *fh = fopen(path, "rb");
    if (!fh) {
        return NULL;
    }
    fseek(fh, 0, SEEK_END);
    long size = ftell(fh);
    fseek(fh, 0, SEEK_SET);
    char *data = (char *)calloc((size_t)size + 1, 1);
    if (!data) {
        fclose(fh);
        return NULL;
    }
    fread(data, 1, (size_t)size, fh);
    fclose(fh);
    return data;
}

static void usage(const char *argv0) {
    fprintf(stderr, "usage: %s --device \\\\.\\Name --ioctls ioctl.json [--persona noob|exp] [--dry-run]\n", argv0);
}

int main(int argc, char **argv) {
    const char *device = NULL;
    const char *ioctl_path = NULL;
    const char *persona = "noob";
    int dry_run = 0;
    DWORD in_size = 0x100;
    DWORD out_size = 0x100;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--device") && i + 1 < argc) {
            device = argv[++i];
        } else if (!strcmp(argv[i], "--ioctls") && i + 1 < argc) {
            ioctl_path = argv[++i];
        } else if (!strcmp(argv[i], "--persona") && i + 1 < argc) {
            persona = argv[++i];
        } else if (!strcmp(argv[i], "--in") && i + 1 < argc) {
            in_size = strtoul(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--out") && i + 1 < argc) {
            out_size = strtoul(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "--dry-run")) {
            dry_run = 1;
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    if (!device || !ioctl_path) {
        usage(argv[0]);
        return 2;
    }

    char *json = read_file(ioctl_path);
    if (!json) {
        fprintf(stderr, "failed to read %s\n", ioctl_path);
        return 1;
    }

    HANDLE h = INVALID_HANDLE_VALUE;
    if (!dry_run) {
        h = CreateFileA(device, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "CreateFile failed for %s: %lu\n", device, GetLastError());
            free(json);
            return 1;
        }
    }

    BYTE *in_buf = (BYTE *)calloc(in_size ? in_size : 1, 1);
    BYTE *out_buf = (BYTE *)calloc(out_size ? out_size : 1, 1);
    char *cursor = json;
    int sent = 0;
    while ((cursor = strstr(cursor, "\"code\"")) != NULL) {
        DWORD code = 0;
        char *colon = strchr(cursor, ':');
        if (colon && parse_hex(colon, &code)) {
            printf("persona=%s device=%s ioctl=0x%08lx", persona, device, (unsigned long)code);
            if (dry_run) {
                printf(" dry-run\n");
            } else {
                DWORD returned = 0;
                BOOL ok = DeviceIoControl(h, code, in_buf, in_size, out_buf, out_size, &returned, NULL);
                printf(" ok=%d gle=%lu returned=%lu\n", ok ? 1 : 0, GetLastError(), (unsigned long)returned);
            }
            sent++;
        }
        cursor += 6;
    }

    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
    }
    free(in_buf);
    free(out_buf);
    free(json);
    return sent == 0 ? 3 : 0;
}
