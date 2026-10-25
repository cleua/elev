#ifndef ELEV_H
#define ELEV_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/types.h>
#include <pwd.h>
#include <stdio.h>

#ifndef CONF_FILE
#define CONF_FILE "/etc/elev.conf"
#endif
#ifndef SAFE_PATH
#define SAFE_PATH "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
#endif

#define GRACE_DIR  "/run/elev"
#define GRACE_SECS (5 * 60)

#define ALLOW  0x5a96c3e1
#define REJECT 0x2c3f1d70

enum {
    F_NOPASS  = 1 << 0,
    F_NOLOG   = 1 << 1,
    F_PERSIST = 1 << 2,
    F_KEEPENV = 1 << 3,
};

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

struct rule {
    int verdict;
    int flags;
    const char *subject;
    const char *runas;
    const char *command;
    const char **args;
    int moreargs;
    const char **env;
};

extern struct rule **ruleset;
extern size_t nruleset;
extern int config_errors;

void load_rules(void);
char **build_env(const struct rule *, const struct passwd *,
                 const struct passwd *);
void ask_password(const struct passwd *);

#ifdef ELEV_GRACE
int grace_open(int *);
void grace_extend(int);
int grace_end(void);
#else
#define grace_open(running) (-1)
#define grace_extend(fd)    ((void)0)
#define grace_end()         0
#endif

#endif
