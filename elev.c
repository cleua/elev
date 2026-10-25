#include "elev.h"

#include <sys/syscall.h>
#include <err.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <paths.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

struct request {
    uid_t caller, target;
    gid_t *groups;
    int ngroups;
    const char *command;
    char **args;
};

static void usage(void)
{
    fputs("usage: elev [-b] [-a user] command [arg ...]\n"
          "       elev [-b] [-a user] -o | -O\n"
          "       elev -x\n", stderr);
    exit(1);
}

static void close_inherited(void)
{
    long fd, limit;

#ifdef SYS_close_range
    if (syscall(SYS_close_range, 3, ~0U, 0) == 0)
        return;
#endif
    if ((limit = sysconf(_SC_OPEN_MAX)) < 0)
        limit = 1024;
    for (fd = 3; fd < limit; fd++)
        close(fd);
}

static int resolve(const char *s, int group, unsigned long *id)
{
    struct passwd *pw = group ? NULL : getpwnam(s);
    struct group *gr = group ? getgrnam(s) : NULL;
    unsigned long long v = 0;

    if (pw || gr) {
        *id = pw ? pw->pw_uid : gr->gr_gid;
        return 0;
    }
    if (*s == '\0')
        return -1;
    for (; *s; s++)
        if (*s < '0' || *s > '9' ||
            (v = v * 10 + (unsigned)(*s - '0')) >= UINT32_MAX)
            return -1;
    *id = (unsigned long)v;
    return 0;
}

static void load_account(uid_t uid, struct passwd *pw)
{
    struct passwd *found = NULL;
    char *buf = NULL;
    size_t size = 512;

    do {
        if (!(buf = realloc(buf, size *= 2)))
            err(1, NULL);
    } while (getpwuid_r(uid, pw, buf, size, &found) == ERANGE);
    if (!found)
        errx(1, "uid %lu has no account", (unsigned long)uid);
    if (!pw->pw_shell || *pw->pw_shell == '\0')
        pw->pw_shell = (char *)_PATH_BSHELL;
}

static int applies(const struct rule *r, const struct request *q)
{
    unsigned long id;
    size_t i;
    int g;

    if (r->subject[0] == ':') {
        if (resolve(r->subject + 1, 1, &id) == -1)
            return 0;
        for (g = 0; g < q->ngroups && q->groups[g] != id; g++)
            ;
        if (g == q->ngroups)
            return 0;
    } else if (resolve(r->subject, 0, &id) == -1 || id != q->caller)
        return 0;
    if (r->runas && (resolve(r->runas, 0, &id) == -1 || id != q->target))
        return 0;
    if (!r->command)
        return 1;
    if (strcmp(r->command, q->command) != 0)
        return 0;
    for (i = 0; r->args && r->args[i]; i++)
        if (!q->args[i] || strcmp(r->args[i], q->args[i]) != 0)
            return 0;
    return !r->args || !q->args[i] || r->moreargs;
}

static const struct rule *decide(const struct request *q)
{
    size_t i = nruleset;

    while (i-- > 0)
        if (applies(ruleset[i], q))
            return ruleset[i];
    return NULL;
}

int main(int argc, char **argv)
{
    struct passwd caller, target;
    struct request q;
    const struct rule *r;
    const char *as = NULL, *base;
    char line[LINE_MAX], cwd[PATH_MAX], *shell[2] = { NULL, NULL };
    char **cmdv, **envp;
    unsigned long id = 0;
    size_t i;
    int c, n, batch = 0, expire = 0, others = 0, mode = 0;
    int running = 0, grace = -1;

    close_inherited();

    while ((c = getopt(argc, argv, "+a:bOox")) != -1) {
        switch (c) {
        case 'a':
            as = optarg;
            break;
        case 'b':
            batch = 1;
            break;
        case 'O':
        case 'o':
            if (mode && mode != c)
                usage();
            mode = c;
            break;
        case 'x':
            expire = 1;
            continue;
        default:
            usage();
        }
        others = 1;
    }
    argc -= optind;
    argv += optind;
    if (expire ? others || argc > 0 : mode ? argc > 0 : argc == 0)
        usage();

    if (geteuid() != 0)
        errx(1, "must be installed setuid root");
    if (expire) {
        if (grace_end() != 0)
            errx(1, "cannot clear grace period");
        return 0;
    }

    if (as && resolve(as, 0, &id) == -1)
        errx(1, "no such user: %s", as);
    q.caller = getuid();
    q.target = (uid_t)id;
    load_account(q.caller, &caller);
    load_account(q.target, &target);

    if ((q.ngroups = getgroups(0, NULL)) == -1 ||
        !(q.groups = calloc((size_t)q.ngroups + 1, sizeof(gid_t))) ||
        (q.ngroups = getgroups(q.ngroups, q.groups)) == -1)
        err(1, "cannot read group list");
    q.groups[q.ngroups++] = getgid();

    load_rules();
    if (config_errors)
        return 1;

    if (mode == 'O') {
        base = strrchr(target.pw_shell, '/');
        if (asprintf(&shell[0], "-%s", base ? base + 1 : target.pw_shell) < 0)
            err(1, NULL);
        q.command = target.pw_shell;
    } else if (mode == 'o') {
        q.command = getenv("SHELL");
        if (!q.command || *q.command == '\0')
            q.command = caller.pw_shell;
        shell[0] = (char *)q.command;
    } else
        q.command = argv[0];
    cmdv = mode ? shell : argv;
    q.args = cmdv + 1;

    n = snprintf(line, sizeof(line), "%s", q.command);
    for (i = 1; cmdv[i] && (size_t)n < sizeof(line); i++)
        n += snprintf(line + n, sizeof(line) - (size_t)n, " %s", cmdv[i]);

    if (!(r = decide(&q)) || r->verdict != ALLOW) {
        syslog(LOG_AUTHPRIV | LOG_NOTICE, "denied user=%s target=%s command=%s",
               caller.pw_name, target.pw_name, line);
        errx(1, "not allowed");
    }

    if (!(r->flags & F_NOPASS)) {
        if (r->flags & F_PERSIST)
            grace = grace_open(&running);
        if (!running) {
            if (batch)
                errx(1, "password needed, but -b was given");
            ask_password(&caller);
        }
        if (grace != -1)
            grace_extend(grace);
    }

    if (setresgid(target.pw_gid, target.pw_gid, target.pw_gid) == -1 ||
        initgroups(target.pw_name, target.pw_gid) == -1 ||
        setresuid(target.pw_uid, target.pw_uid, target.pw_uid) == -1)
        err(1, "cannot switch to %s", target.pw_name);

    if (!(r->flags & F_NOLOG)) {
        if (!getcwd(cwd, sizeof(cwd)))
            strcpy(cwd, "(unknown)");
        syslog(LOG_AUTHPRIV | LOG_INFO,
               "granted user=%s target=%s cwd=%s command=%s",
               caller.pw_name, target.pw_name, cwd, line);
    }
    if (mode == 'O' && chdir(target.pw_dir) == -1)
        warn("%s", target.pw_dir);

    envp = build_env(r, &caller, &target);

    if ((r->command || !getenv("PATH")) && setenv("PATH", SAFE_PATH, 1) == -1)
        err(1, "setenv");
    execvpe(q.command, cmdv, envp);
    if (errno == ENOENT)
        errx(1, "%s: no such command", q.command);
    err(1, "cannot run %s", q.command);
}
