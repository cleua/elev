#include "elev.h"

#include <sys/stat.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define SKIP4 " %*s %*s %*s %*s"
#define STAT_FIELDS SKIP4 " %lld" SKIP4 SKIP4 SKIP4 " %*s %*s %llu"

static int grace_prepare(char *name, size_t size)
{
    char path[64], text[4096], *p;
    long long tty;
    unsigned long long start;
    pid_t parent = getppid();
    struct stat st;
    ssize_t n;
    int fd;

    snprintf(path, sizeof(path), "/proc/%ld/stat", (long)parent);
    if ((fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)) == -1) {
        warn("%s", path);
        return -1;
    }
    n = read(fd, text, sizeof(text) - 1);
    close(fd);
    if (n <= 0 || memchr(text, '\0', (size_t)n))
        return -1;
    text[n] = '\0';
    if (!(p = strrchr(text, ')')) ||
        sscanf(p + 1, STAT_FIELDS, &tty, &start) != 2)
        return -1;
    snprintf(name, size, "%ld.%ld.%lld.%llu.%lu", (long)parent,
             (long)getsid(0), tty, start, (unsigned long)getuid());

    if (mkdir(GRACE_DIR, 0700) == -1 && errno != EEXIST)
        return -1;
    fd = open(GRACE_DIR, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd == -1)
        return -1;
    if (fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == 0 &&
        fchown(fd, 0, 0) == 0 && fchmod(fd, 0700) == 0)
        return fd;
    close(fd);
    return -1;
}

static int ahead(clockid_t clock, const struct timespec *t)
{
    struct timespec now;
    long long secs;

    if (clock_gettime(clock, &now) == -1)
        return 0;
    secs = (long long)t->tv_sec - (long long)now.tv_sec -
           (t->tv_nsec < now.tv_nsec);
    return secs >= 0 && secs < GRACE_SECS;
}

int grace_open(int *running)
{
    static const struct timespec never[2];
    char name[128], tmp[32];
    struct stat st;
    int dir, fd;

    *running = 0;
    if ((dir = grace_prepare(name, sizeof(name))) == -1)
        return -1;

    if ((fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)) != -1) {
        if (fstat(fd, &st) == -1 || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
            (st.st_mode & 07777) != 0)
            errx(1, "grace record has wrong owner or mode");
        *running = ahead(CLOCK_BOOTTIME, &st.st_atim) &&
                   ahead(CLOCK_REALTIME, &st.st_mtim);
    } else if (errno == ENOENT) {
        snprintf(tmp, sizeof(tmp), ".new.%ld", (long)getpid());
        fd = openat(dir, tmp, O_RDONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                    O_CLOEXEC, 0);
        if (fd == -1 || futimens(fd, never) == -1 ||
            renameat(dir, tmp, dir, name) == -1) {
            if (fd != -1)
                close(fd);
            unlinkat(dir, tmp, 0);
            fd = -1;
        }
    } else
        err(1, "cannot open grace record %s", name);

    close(dir);
    return fd;
}

void grace_extend(int fd)
{
    struct timespec until[2];

    if (clock_gettime(CLOCK_BOOTTIME, &until[0]) == 0 &&
        clock_gettime(CLOCK_REALTIME, &until[1]) == 0) {
        until[0].tv_sec += GRACE_SECS;
        until[1].tv_sec += GRACE_SECS;
        futimens(fd, until);
    }
    close(fd);
}

int grace_end(void)
{
    char name[128];
    int dir, rc;

    if ((dir = grace_prepare(name, sizeof(name))) == -1)
        return -1;
    if ((rc = unlinkat(dir, name, 0)) == -1 && errno == ENOENT)
        rc = 0;
    close(dir);
    return rc;
}
