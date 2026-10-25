#include "elev.h"

#include <err.h>
#include <stdlib.h>
#include <string.h>

extern char **environ;

static char **vars;
static size_t nvars;

static long find(const char *name, size_t n)
{
    size_t i;

    for (i = 0; i < nvars; i++)
        if (strncmp(vars[i], name, n) == 0 && vars[i][n] == '=')
            return (long)i;
    return -1;
}

static void set(const char *name, size_t n, const char *val)
{
    long i = find(name, n);
    char *s = NULL;

    if (val && asprintf(&s, "%.*s=%s", (int)n, name, val) == -1)
        err(1, NULL);
    if (i == -1) {
        if (!s)
            return;
        if (!(vars = realloc(vars, (nvars + 2) * sizeof(*vars))))
            err(1, NULL);
        i = (long)nvars++;
    } else
        free(vars[i]);
    vars[i] = s ? s : vars[--nvars];
    vars[nvars] = NULL;
}

char **build_env(const struct rule *r, const struct passwd *caller,
                 const struct passwd *target)
{
    static const char *const keep[] = {
        "DISPLAY", "LANG", "TERM", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR",
    };
    const char *base[][2] = {
        { "ELEV_CALLER", caller->pw_name },
        { "HOME",        target->pw_dir },
        { "LOGNAME",     target->pw_name },
        { "USER",        target->pw_name },
        { "PATH",        SAFE_PATH },
        { "SHELL",       target->pw_shell },
    };
    const char *s, *eq, *val;
    size_t i, k, n;
    char **p;

    for (i = 0; i < COUNT(base); i++)
        set(base[i][0], strlen(base[i][0]), base[i][1]);

    for (p = environ; *p; p++) {
        if (!(eq = strchr(*p, '=')) || eq == *p)
            continue;
        n = (size_t)(eq - *p);
        for (k = 0; k < COUNT(keep); k++)
            if (strlen(keep[k]) == n && memcmp(*p, keep[k], n) == 0)
                break;
        if (find(*p, n) == -1 && ((r->flags & F_KEEPENV) ||
            k < COUNT(keep) || strncmp(*p, "LC_", 3) == 0))
            set(*p, n, eq + 1);
    }

    for (i = 0; r->env && (s = r->env[i]); i++) {
        if (*s == '-') {
            set(s + 1, strlen(s + 1), NULL);
            continue;
        }
        if ((eq = strchr(s, '='))) {
            n = (size_t)(eq - s);
            val = eq[1] == '$' && eq[2] ? getenv(eq + 2) : eq + 1;
        } else {
            n = strlen(s);
            val = getenv(s);
        }
        if (n)
            set(s, n, val);
    }
    return vars;
}
