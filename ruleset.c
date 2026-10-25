#include "elev.h"

#include <sys/stat.h>
#include <err.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#define WORD_MAX 1024

enum {
    T_EOL = 256, T_OPEN, T_CLOSE, T_WORD, T_END,
    T_PERMIT, T_DENY, T_AS, T_CMD, T_ARGS, T_ANY, T_SETENV,
    T_NOPASS, T_NOLOG, T_PERSIST, T_KEEPENV,
};

static const char *const reserved[] = {
    "permit", "deny", "as", "cmd", "args", "*", "setenv",
    "nopass", "nolog", "persist", "keepenv",
};

struct rule **ruleset;
size_t nruleset;
int config_errors;

static struct {
    FILE *fp;
    int line, col;
    int ended;
    int ahead;
    char *word;
} in;

static int complain(const char *fmt, ...)
{
    va_list ap;

    fprintf(stderr, "elev: %s:%d: ", CONF_FILE, in.line);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    config_errors++;
    return -1;
}

static int getch(void)
{
    int c = getc(in.fp);

    if (c != EOF)
        in.col++;
    return c;
}

static void ungetch(int c)
{
    if (c != EOF && ungetc(c, in.fp) != EOF)
        in.col--;
}

static int line_end(int c)
{
    if (c == EOF) {
        if (in.ended)
            return T_END;
        in.ended = 1;
        if (ferror(in.fp))
            complain("read error");
    }
    in.line++;
    in.col = 0;
    return T_EOL;
}

static int scan(void)
{
    enum { BLANK, WORD, QUOTED } st = BLANK;
    char buf[WORD_MAX];
    size_t len = 0, i;
    int c, col, plain = 1, quoted = 0, qcol = 0;

    for (;;) {
        c = getch();
        if (c == '\\') {
            col = in.col;
            if ((c = getch()) == '\n') {
                in.line++;
                in.col = 0;
                plain &= st == BLANK;
                continue;
            }
            if (c == EOF) {
                complain("backslash at end of input in column %d", col);
                if (st == BLANK)
                    continue;
                goto done;
            }
            if (st == BLANK)
                st = WORD;
            plain = 0;
        } else if (st == QUOTED) {
            if (c == '"') {
                st = WORD;
                continue;
            }
            if (c == '\n' || c == EOF) {
                complain("unclosed quote from column %d", qcol);
                ungetch(c);
                goto done;
            }
        } else {
            if (st == BLANK) {
                if (c == ' ' || c == '\t')
                    continue;
                if (c == '#')
                    while (c != '\n' && c != EOF)
                        c = getch();
                if (c == '\n' || c == EOF)
                    return line_end(c);
                if (c == '{' || c == '}') {
                    in.col--;
                    return c == '{' ? T_OPEN : T_CLOSE;
                }
                st = WORD;
            }
            if (c == '"') {
                st = QUOTED;
                qcol = in.col;
                plain = 0;
                quoted = 1;
                continue;
            }
            if (c == EOF || (c && strchr(" \t\n#{}", c))) {
                if (c != ' ' && c != '\t')
                    ungetch(c);
                goto done;
            }
        }
        if (c == '\0') {
            complain("NUL byte in column %d", in.col);
            continue;
        }
        if (len == sizeof(buf) - 1) {
            complain("word longer than %d bytes", WORD_MAX - 1);
            len = 0;
        }
        buf[len++] = (char)c;
        continue;
    done:
        if (len > 0 || quoted)
            break;
        st = BLANK;
        plain = 1;
    }

    buf[len] = '\0';
    for (i = 0; plain && i < COUNT(reserved); i++)
        if (strcmp(buf, reserved[i]) == 0)
            return T_PERMIT + (int)i;
    if (!(in.word = strdup(buf)))
        err(1, NULL);
    return T_WORD;
}

static int peek(void)
{
    if (in.ahead == -1)
        in.ahead = scan();
    return in.ahead;
}

static int take(void)
{
    int t = peek();

    in.ahead = -1;
    return t;
}

static int accept(int tok)
{
    return peek() == tok && take();
}

static const char *word(void)
{
    return peek() == T_WORD && take() ? in.word : NULL;
}

static const char **words(void)
{
    const char **v = NULL;
    size_t n = 0;

    do {
        if (!(v = realloc(v, (n + 1) * sizeof(*v))))
            err(1, NULL);
    } while ((v[n++] = word()));
    return v;
}

static int parse_rule(void)
{
    struct rule *r = calloc(1, sizeof(*r));
    int before = config_errors, t;

    if (!r)
        err(1, NULL);
    if (accept(T_DENY))
        r->verdict = REJECT;
    else if (!accept(T_PERMIT))
        return complain("malformed rule");
    else
        for (r->verdict = ALLOW;; ) {
            if ((t = peek()) >= T_NOPASS && t <= T_KEEPENV) {
                take();
                r->flags |= 1 << (t - T_NOPASS);
                if ((r->flags & F_NOPASS) && (r->flags & F_PERSIST))
                    return complain("nopass and persist cannot be combined");
            } else if (t == T_SETENV) {
                if (r->env)
                    return complain("more than one setenv section");
                take();
                if (!accept(T_OPEN) || !(r->env = words()) || !accept(T_CLOSE))
                    return complain("malformed rule");
            } else
                break;
        }

    if (!(r->subject = word()) || (accept(T_AS) && !(r->runas = word())))
        return complain("malformed rule");
    if (accept(T_CMD)) {
        if (!(r->command = word()))
            return complain("malformed rule");
        if (accept(T_ARGS)) {
            r->args = words();
            r->moreargs = accept(T_ANY);
        }
    }
    if (!accept(T_EOL) && peek() != T_END)
        return complain("malformed rule");

    if (config_errors == before) {
        ruleset = realloc(ruleset, (nruleset + 1) * sizeof(*ruleset));
        if (!ruleset)
            err(1, NULL);
        ruleset[nruleset++] = r;
    }
    return 0;
}

void load_rules(void)
{
    struct stat st;

    if (!(in.fp = fopen(CONF_FILE, "r")))
        err(1, errno == ENOENT ? "no rules at %s" : "cannot open %s",
            CONF_FILE);
    if (fstat(fileno(in.fp), &st) == -1)
        err(1, "%s", CONF_FILE);
    if (st.st_mode & (S_IWGRP | S_IWOTH))
        errx(1, "refusing %s: writable by group or others", CONF_FILE);
    if (st.st_uid != 0)
        errx(1, "refusing %s: not owned by root", CONF_FILE);

    in.line = 1;
    in.ahead = -1;
    while (peek() != T_END)
        if (!accept(T_EOL) && parse_rule() == -1)
            while (peek() != T_END && !accept(T_EOL))
                take();
    fclose(in.fp);
}
