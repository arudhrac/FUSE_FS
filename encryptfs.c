

#define FUSE_USE_VERSION 31

#include <fuse3/fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <pthread.h>
#include <limits.h>
#include <stdint.h>
#include <openssl/rand.h>

#include "../include/encryptfs.h"
#include "../include/crypto.h"

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

/* Shortcut to retrieve the efs_state_t stored as FUSE private_data */
#define EFS ((efs_state_t *)fuse_get_context()->private_data)

static void to_backing(char out[PATH_MAX], const char *vpath)
{
    snprintf(out, PATH_MAX, "%s%s", EFS->backing, vpath);
}

/* Return non-zero if this filename is internal to encryptfs (hidden from VFS) */
static int is_hidden(const char *name)
{
    return strcmp(name, EFS_CONFIG_FILE) == 0;
}

static uint8_t *backing_read_decrypt(const char *bpath,
                                      size_t *pt_len, int *err)
{
    *pt_len = 0;
    *err    = 0;

    FILE *f = fopen(bpath, "rb");
    if (!f) { *err = errno; return NULL; }

    fseek(f, 0, SEEK_END);
    long raw_sz = ftell(f);
    rewind(f);

    if (raw_sz == 0) { fclose(f); return NULL; } /* empty = empty plaintext */

    if (raw_sz < (long)EFS_HDR_LEN) {
        fclose(f);
        fprintf(stderr, "encryptfs: %s: file too small (%ld B) for header\n",
                bpath, raw_sz);
        *err = EIO;
        return NULL;
    }

    uint8_t *raw = malloc((size_t)raw_sz);
    if (!raw) { fclose(f); *err = ENOMEM; return NULL; }

    if (fread(raw, 1, (size_t)raw_sz, f) != (size_t)raw_sz) {
        fclose(f); free(raw); *err = EIO; return NULL;
    }
    fclose(f);

    /* Parse header: [IV 12B][TAG 16B][ciphertext ...] */
    const uint8_t *iv  = raw;
    const uint8_t *tag = raw + EFS_IV_LEN;
    const uint8_t *ct  = raw + EFS_HDR_LEN;
    size_t         ct_sz = (size_t)raw_sz - EFS_HDR_LEN;

    uint8_t *plain = malloc(ct_sz + 1); /* +1 so caller can safely NUL-terminate */
    if (!plain) { free(raw); *err = ENOMEM; return NULL; }

    int res = efs_decrypt(EFS->key, iv, tag, ct, ct_sz, plain);
    free(raw);

    if (res < 0) {
        free(plain);
        if (res == -EBADMSG)
            fprintf(stderr, "encryptfs: %s: authentication failed "
                    "(tampered file or wrong password)\n", bpath);
        else
            fprintf(stderr, "encryptfs: %s: decryption error\n", bpath);
        *err = EIO;
        return NULL;
    }

    *pt_len = (size_t)res;
    return plain;
}


static int backing_encrypt_write(const char *bpath,
                                  const uint8_t *plain, size_t pt_len)
{
    uint8_t  iv[EFS_IV_LEN], tag[EFS_TAG_LEN];
    /* GCM ciphertext is same length as plaintext — no padding */
    uint8_t *ct = malloc(pt_len + 1);
    if (!ct) return -ENOMEM;

    int ct_len = efs_encrypt(EFS->key, plain, pt_len, iv, tag, ct);
    if (ct_len < 0) { free(ct); return -EIO; }

    FILE *f = fopen(bpath, "wb");
    if (!f) { free(ct); return -errno; }

    /* Write: IV → TAG → ciphertext (must all succeed) */
    int ok = (fwrite(iv,  1, EFS_IV_LEN,        f) == EFS_IV_LEN)
          && (fwrite(tag, 1, EFS_TAG_LEN,        f) == EFS_TAG_LEN)
          && (fwrite(ct,  1, (size_t)ct_len, f) == (size_t)ct_len);

    int save_errno = errno;
    fclose(f);
    free(ct);

    if (!ok) { errno = save_errno; return -EIO; }
    return 0;
}


static int efs_getattr(const char *path, struct stat *st,
                        struct fuse_file_info *fi)
{
    (void)fi;
    char bpath[PATH_MAX];
    to_backing(bpath, path);

    /* Hide our internal config file */
    if (strcmp(path + 1, EFS_CONFIG_FILE) == 0)
        return -ENOENT;

    if (lstat(bpath, st) < 0)
        return -errno;

    if (S_ISREG(st->st_mode)) {
        if (st->st_size >= (off_t)EFS_HDR_LEN)
            st->st_size -= (off_t)EFS_HDR_LEN;
        else
            st->st_size = 0; /* empty or corrupt — show as empty */
    }

    return 0;
}


static int efs_access(const char *path, int mask)
{
    char bpath[PATH_MAX];
    to_backing(bpath, path);
    return access(bpath, mask) < 0 ? -errno : 0;
}

/* ── readdir: list a directory ───────────────────────────── */
static int efs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi,
                        enum fuse_readdir_flags flags)
{
    (void)offset; (void)fi; (void)flags;

    char bpath[PATH_MAX];
    to_backing(bpath, path);

    DIR *dp = opendir(bpath);
    if (!dp) return -errno;

    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (is_hidden(de->d_name)) continue; /* hide config file */

        struct stat st = {0};
        st.st_ino  = de->d_ino;
        st.st_mode = DTTOIF(de->d_type); /* d_type → mode_t conversion */

        if (filler(buf, de->d_name, &st, 0, 0) != 0)
            break; /* buffer full */
    }

    closedir(dp);
    return 0;
}

/* ── readlink: read the target of a symlink ──────────────── */
static int efs_readlink(const char *path, char *buf, size_t size)
{
    char bpath[PATH_MAX];
    to_backing(bpath, path);

    ssize_t n = readlink(bpath, buf, size - 1);
    if (n < 0) return -errno;
    buf[n] = '\0';
    return 0;
}

static int efs_open(const char *path, struct fuse_file_info *fi)
{
    char bpath[PATH_MAX];
    to_backing(bpath, path);

    /* Strip creation flags — those belong in create() */
    int fd = open(bpath, fi->flags & ~(O_CREAT | O_TRUNC | O_EXCL));
    if (fd < 0) return -errno;
    close(fd);
    return 0;
}

static int efs_read(const char *path, char *buf, size_t size, off_t offset,
                     struct fuse_file_info *fi)
{
    (void)fi;
    char bpath[PATH_MAX];
    to_backing(bpath, path);

    pthread_mutex_lock(&g_lock);

    int      dec_err = 0;
    size_t   pt_len  = 0;
    uint8_t *plain   = backing_read_decrypt(bpath, &pt_len, &dec_err);

    pthread_mutex_unlock(&g_lock);

    if (!plain) {
        if (dec_err) return -dec_err;
        return 0; /* empty file → 0 bytes read */
    }

    int ret;
    if ((size_t)offset >= pt_len) {
        ret = 0; /* read past EOF */
    } else {
        if ((size_t)offset + size > pt_len)
            size = pt_len - (size_t)offset; /* clamp to available */
        memcpy(buf, plain + offset, size);
        ret = (int)size;
    }

    /* Security: zero the plaintext buffer before freeing */
    memset(plain, 0, pt_len);
    free(plain);
    return ret;
}

static int efs_write(const char *path, const char *buf, size_t size,
                      off_t offset, struct fuse_file_info *fi)
{
    (void)fi;
    char bpath[PATH_MAX];
    to_backing(bpath, path);

    pthread_mutex_lock(&g_lock);

    /* Step 1: Read + decrypt existing content (may be empty) */
    int      dec_err = 0;
    size_t   pt_len  = 0;
    uint8_t *plain   = backing_read_decrypt(bpath, &pt_len, &dec_err);

    if (dec_err) {
        pthread_mutex_unlock(&g_lock);
        return -dec_err;
    }

    /* Step 2: Compute required new plaintext length */
    size_t new_len = (size_t)offset + size;
    if (new_len < pt_len) new_len = pt_len; /* keep existing tail */

    /* Step 3: Resize the plaintext buffer */
    uint8_t *new_plain = realloc(plain, new_len + 1);
    if (!new_plain) {
        if (plain) { memset(plain, 0, pt_len); free(plain); }
        pthread_mutex_unlock(&g_lock);
        return -ENOMEM;
    }
    plain = new_plain;

    /* Zero-fill any gap between old EOF and the write offset (POSIX requires this) */
    if ((size_t)offset > pt_len)
        memset(plain + pt_len, 0, (size_t)offset - pt_len);

    /* Step 4: Apply the write at the requested offset */
    memcpy(plain + offset, buf, size);

    /* Step 5: Re-encrypt with a NEW random IV and write back */
    int res = backing_encrypt_write(bpath, plain, new_len);

    memset(plain, 0, new_len);
    free(plain);
    pthread_mutex_unlock(&g_lock);

    return (res < 0) ? res : (int)size;
}

/* ── create: create a new regular file ──────────────────────*/
static int efs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    (void)fi;
    char bpath[PATH_MAX];
    to_backing(bpath, path);

    /* Create an empty backing file. write() will populate it later. */
    int fd = open(bpath, O_CREAT | O_WRONLY | O_TRUNC, mode);
    if (fd < 0) return -errno;
    close(fd);
    return 0;
}

/* ── truncate: resize a file ─────────────────────────────── */
static int efs_truncate(const char *path, off_t new_size,
                         struct fuse_file_info *fi)
{
    (void)fi;
    char bpath[PATH_MAX];
    to_backing(bpath, path);

    pthread_mutex_lock(&g_lock);
    int ret = 0;

    if (new_size == 0) {
        /* Fast path: truncate to empty = empty backing file */
        int fd = open(bpath, O_WRONLY | O_TRUNC);
        if (fd < 0) ret = -errno;
        else close(fd);
        pthread_mutex_unlock(&g_lock);
        return ret;
    }

    /* General case: read-decrypt-resize-re-encrypt-write */
    int      dec_err = 0;
    size_t   pt_len  = 0;
    uint8_t *plain   = backing_read_decrypt(bpath, &pt_len, &dec_err);

    if (dec_err) { pthread_mutex_unlock(&g_lock); return -dec_err; }

    size_t target = (size_t)new_size;
    uint8_t *resized = realloc(plain, target + 1);
    if (!resized) {
        if (plain) { memset(plain, 0, pt_len); free(plain); }
        pthread_mutex_unlock(&g_lock);
        return -ENOMEM;
    }
    plain = resized;

    if (target > pt_len)
        memset(plain + pt_len, 0, target - pt_len); /* zero extend */

    ret = backing_encrypt_write(bpath, plain, target);
    memset(plain, 0, target);
    free(plain);

    pthread_mutex_unlock(&g_lock);
    return ret;
}

static int efs_mkdir(const char *path, mode_t mode)
{
    char bpath[PATH_MAX];
    to_backing(bpath, path);
    return mkdir(bpath, mode) < 0 ? -errno : 0;
}

static int efs_rmdir(const char *path)
{
    char bpath[PATH_MAX];
    to_backing(bpath, path);
    return rmdir(bpath) < 0 ? -errno : 0;
}

static int efs_unlink(const char *path)
{
    char bpath[PATH_MAX];
    to_backing(bpath, path);
    return unlink(bpath) < 0 ? -errno : 0;
}

static int efs_rename(const char *from, const char *to, unsigned int flags)
{
    (void)flags;
    char bf[PATH_MAX], bt[PATH_MAX];
    to_backing(bf, from);
    to_backing(bt, to);
    return rename(bf, bt) < 0 ? -errno : 0;
}

static int efs_symlink(const char *target, const char *linkpath)
{
    char blink[PATH_MAX];
    to_backing(blink, linkpath);
    /* NOTE: target is NOT translated — it's the symlink destination as-is */
    return symlink(target, blink) < 0 ? -errno : 0;
}

static int efs_link(const char *from, const char *to)
{
    char bf[PATH_MAX], bt[PATH_MAX];
    to_backing(bf, from);
    to_backing(bt, to);
    return link(bf, bt) < 0 ? -errno : 0;
}

static int efs_chmod(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    (void)fi;
    char bpath[PATH_MAX];
    to_backing(bpath, path);
    return chmod(bpath, mode) < 0 ? -errno : 0;
}

static int efs_chown(const char *path, uid_t uid, gid_t gid,
                      struct fuse_file_info *fi)
{
    (void)fi;
    char bpath[PATH_MAX];
    to_backing(bpath, path);
    return lchown(bpath, uid, gid) < 0 ? -errno : 0;
}

static int efs_utimens(const char *path, const struct timespec tv[2],
                        struct fuse_file_info *fi)
{
    (void)fi;
    char bpath[PATH_MAX];
    to_backing(bpath, path);
    return utimensat(AT_FDCWD, bpath, tv, AT_SYMLINK_NOFOLLOW) < 0 ? -errno : 0;
}

static int efs_statfs(const char *path, struct statvfs *stbuf)
{
    char bpath[PATH_MAX];
    to_backing(bpath, path);
    return statvfs(bpath, stbuf) < 0 ? -errno : 0;
}

static int efs_release(const char *path, struct fuse_file_info *fi)
{
    (void)path; (void)fi;
    return 0; /* We don't hold open fds between calls */
}

static int efs_fsync(const char *path, int isdatasync, struct fuse_file_info *fi)
{
    (void)path; (void)isdatasync; (void)fi;
    return 0; /* We write synchronously in write() */
}

/* ─── fuse_operations registration table ─────────────────── */
static const struct fuse_operations efs_ops = {
    .getattr  = efs_getattr,
    .access   = efs_access,
    .readlink = efs_readlink,
    .readdir  = efs_readdir,
    .mkdir    = efs_mkdir,
    .symlink  = efs_symlink,
    .unlink   = efs_unlink,
    .rmdir    = efs_rmdir,
    .rename   = efs_rename,
    .link     = efs_link,
    .chmod    = efs_chmod,
    .chown    = efs_chown,
    .truncate = efs_truncate,
    .open     = efs_open,
    .create   = efs_create,
    .read     = efs_read,
    .write    = efs_write,
    .statfs   = efs_statfs,
    .release  = efs_release,
    .fsync    = efs_fsync,
    .utimens  = efs_utimens,
};

/* ─── Config file management ──────────────────────────────── */
static int efs_init_config(const char *backing, uint8_t salt[EFS_SALT_LEN])
{
    char cfg_path[PATH_MAX];
    snprintf(cfg_path, PATH_MAX, "%s/%s", backing, EFS_CONFIG_FILE);

    if (efs_generate_salt(salt) < 0)
        return -1;

    /* O_EXCL: fail if config already exists (prevents accidental overwrite) */
    int fd = open(cfg_path, O_CREAT | O_WRONLY | O_EXCL, 0600);
    if (fd < 0) {
        fprintf(stderr, "encryptfs: cannot create config %s: %s\n",
                cfg_path, strerror(errno));
        return -1;
    }

    /* Write: magic (10 bytes) + salt (32 bytes) = 42 bytes total */
    ssize_t wm = write(fd, EFS_MAGIC, EFS_MAGIC_LEN);
    ssize_t ws = write(fd, salt, EFS_SALT_LEN);
    close(fd);

    if (wm != EFS_MAGIC_LEN || ws != EFS_SALT_LEN) {
        unlink(cfg_path);
        fprintf(stderr, "encryptfs: failed to write config\n");
        return -1;
    }

    fprintf(stderr, "encryptfs: [init] new filesystem created. Salt saved to %s\n",
            cfg_path);
    return 0;
}

static int efs_load_config(const char *backing, uint8_t salt[EFS_SALT_LEN])
{
    char cfg_path[PATH_MAX];
    snprintf(cfg_path, PATH_MAX, "%s/%s", backing, EFS_CONFIG_FILE);

    int fd = open(cfg_path, O_RDONLY);
    if (fd < 0) return -1; /* does not exist */

    char magic[EFS_MAGIC_LEN + 1] = {0};
    if (read(fd, magic, EFS_MAGIC_LEN) != EFS_MAGIC_LEN) {
        close(fd);
        fprintf(stderr, "encryptfs: config read error\n");
        return -1;
    }

    if (memcmp(magic, EFS_MAGIC, EFS_MAGIC_LEN) != 0) {
        close(fd);
        fprintf(stderr, "encryptfs: config bad magic (expected %s)\n", EFS_MAGIC);
        return -1;
    }

    if (read(fd, salt, EFS_SALT_LEN) != EFS_SALT_LEN) {
        close(fd);
        fprintf(stderr, "encryptfs: config truncated\n");
        return -1;
    }

    close(fd);
    fprintf(stderr, "encryptfs: [load] existing filesystem config found\n");
    return 0;
}

/* ─── Usage ───────────────────────────────────────────────── */
static void usage(const char *prog)
{
    fprintf(stderr,
        "\n"
        "  encryptfs — AES-256-GCM encrypted FUSE filesystem\n"
        "\n"
        "  Usage: %s <backing_dir> <mountpoint> --password=<pass> [fuse_opts]\n"
        "\n"
        "  backing_dir   Where encrypted files are stored on disk\n"
        "  mountpoint    Where decrypted files appear (must exist, must be empty)\n"
        "  --password=   Passphrase for AES-256 key derivation (PBKDF2-SHA256)\n"
        "\n"
        "  FUSE options (append after --password=...):\n"
        "    -f           Foreground mode (Ctrl+C to unmount)\n"
        "    -d           Debug mode (very verbose)\n"
        "    -s           Single-threaded mode\n"
        "\n"
        "  First mount: initializes the filesystem (generates random salt).\n"
        "  Re-mount:    reads existing salt, derives the same key.\n"
        "\n"
        "  Unmount: fusermount3 -u <mountpoint>\n"
        "\n"
        "  Example:\n"
        "    mkdir /tmp/backing /tmp/secret\n"
        "    %s /tmp/backing /tmp/secret --password=mysecret -f\n"
        "    echo 'top secret' > /tmp/secret/notes.txt\n"
        "    cat /tmp/secret/notes.txt        # → top secret\n"
        "    xxd /tmp/backing/notes.txt       # → random bytes\n"
        "    fusermount3 -u /tmp/secret\n"
        "\n",
        prog, prog);
}

/* ─── main ───────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    if (argc < 4) { usage(argv[0]); return 1; }

    /* ── Parse our custom arguments ── */
    char *backing  = argv[1];
    char *password = NULL;

    /*
     * FUSE expects: program [fuse-opts] mountpoint
     * We add backing_dir as argv[1], so we:
     *   1. Pass argv[0] (program name) to FUSE
     *   2. Skip argv[1] (our backing_dir)
     *   3. Pass argv[2..] to FUSE, minus our --password= arg
     */
    struct fuse_args fargs = FUSE_ARGS_INIT(0, NULL);
    fuse_opt_add_arg(&fargs, argv[0]);

    for (int i = 2; i < argc; i++) {
        if (strncmp(argv[i], "--password=", 11) == 0) {
            password = argv[i] + 11;
        } else {
            fuse_opt_add_arg(&fargs, argv[i]);
        }
    }

    if (!password || strlen(password) == 0) {
        fprintf(stderr, "encryptfs: error: --password=<pass> is required\n");
        fuse_opt_free_args(&fargs);
        usage(argv[0]);
        return 1;
    }

    /* ── Validate backing directory ── */
    struct stat sbuf;
    if (stat(backing, &sbuf) < 0 || !S_ISDIR(sbuf.st_mode)) {
        fprintf(stderr, "encryptfs: backing directory not found: %s\n", backing);
        fuse_opt_free_args(&fargs);
        return 1;
    }

    /* ── Load or initialize config (salt) ── */
    uint8_t salt[EFS_SALT_LEN];
    if (efs_load_config(backing, salt) < 0) {
        fprintf(stderr, "encryptfs: no config found — initializing...\n");
        if (efs_init_config(backing, salt) < 0) {
            fuse_opt_free_args(&fargs);
            return 1;
        }
    }

    /* ── Build filesystem state ── */
    efs_state_t *state = calloc(1, sizeof(efs_state_t));
    if (!state) {
        fuse_opt_free_args(&fargs);
        return 1;
    }

    if (!realpath(backing, state->backing)) {
        fprintf(stderr, "encryptfs: realpath(%s): %s\n", backing, strerror(errno));
        free(state);
        fuse_opt_free_args(&fargs);
        return 1;
    }

    /* ── Derive AES-256 key from password + salt ── */
    fprintf(stderr, "encryptfs: deriving key (PBKDF2-SHA256, %d iterations)...\n",
            EFS_PBKDF2_ITER);

    if (efs_derive_key(password, salt, state->key) < 0) {
        free(state);
        fuse_opt_free_args(&fargs);
        return 1;
    }

    /*
     * Security: zero password from argv immediately after key derivation.
     * The key is the only sensitive material we need going forward.
     */
    memset(password, 0, strlen(password));

    fprintf(stderr, "encryptfs: key ready. mounting %s → %s\n",
            state->backing, fargs.argv[fargs.argc - 1]);
    fprintf(stderr, "encryptfs: (unmount with: fusermount3 -u %s)\n\n",
            fargs.argv[fargs.argc - 1]);

    /* ── Start FUSE event loop ── */
    int ret = fuse_main(fargs.argc, fargs.argv, &efs_ops, state);

    /* ── Cleanup on unmount ── */
    memset(state->key, 0, EFS_KEY_LEN); /* zero the key before freeing */
    free(state);
    fuse_opt_free_args(&fargs);
    return ret;
}
