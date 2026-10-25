#include "elev.h"

#include <crypt.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <paths.h>
#include <shadow.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <termios.h>
#include <unistd.h>

#define MAX_TRIES 3

static const int watched[] = {
    SIGALRM, SIGHUP, SIGINT, SIGPIPE, SIGQUIT, SIGTERM,
    SIGTSTP, SIGTTIN, SIGTTOU,
};
static volatile sig_atomic_t pending[NSIG], any;

static void note(int sig)
{
    pending[sig] = any = 1;
}

static void trap(int on)
{
    static struct sigaction saved[COUNT(watched)];
    struct sigaction sa;
    size_t i;

    memset(&sa, 0, sizeof(sa));
    sigfillset(&sa.sa_mask);
    sa.sa_handler = note;
    any = 0;
    for (i = 0; i < COUNT(watched); i++) {
        if (on) {
            pending[watched[i]] = 0;
            sigaction(watched[i], &sa, &saved[i]);
        } else
            sigaction(watched[i], &saved[i], NULL);
    }
}

static int reraise(void)
{
    int stopped = 0, other = 0, s;
    size_t i;

    for (i = 0; i < COUNT(watched); i++) {
        if (!pending[s = watched[i]])
            continue;
        kill(getpid(), s);
        if (s == SIGTSTP || s == SIGTTIN || s == SIGTTOU)
            stopped = 1;
        else
            other = 1;
    }
    return other ? -1 : stopped;
}

static void read_secret(const char *prompt, char *buf, size_t size,
                        const char *user)
{
    struct termios orig, quiet;
    sigset_t ttou, mask;
    size_t len;
    ssize_t n;
    char c;
    int fd, e, sig;

    for (;;) {
        if ((fd = open(_PATH_TTY, O_RDWR | O_CLOEXEC)) == -1 ||
            tcgetattr(fd, &orig) == -1) {
            syslog(LOG_AUTHPRIV | LOG_NOTICE, "no tty user=%s", user);
            errx(1, "no terminal to read a password from");
        }
        trap(1);
        quiet = orig;
        quiet.c_lflag &= ~(tcflag_t)(ECHO | ECHONL);
        e = 0;
        if (tcsetattr(fd, TCSAFLUSH, &quiet) == -1 ||
            write(fd, prompt, strlen(prompt)) == -1)
            e = errno;
        for (len = 0; !e && !any;) {
            if ((n = read(fd, &c, 1)) < 0)
                e = errno;
            else if (n == 0 || c == '\n' || c == '\r')
                break;
            else if (len + 1 < size)
                buf[len++] = c;
        }
        buf[len] = '\0';

        sigemptyset(&ttou);
        sigaddset(&ttou, SIGTTOU);
        sigprocmask(SIG_BLOCK, &ttou, &mask);
        n = write(fd, "\n", 1);
        tcsetattr(fd, TCSAFLUSH, &orig);
        sigprocmask(SIG_SETMASK, &mask, NULL);
        close(fd);
        trap(0);

        if ((sig = reraise()) == 0 && e == 0)
            return;
        explicit_bzero(buf, size);
        if (sig != 1) {
            errno = sig ? EINTR : e;
            err(1, "cannot read password");
        }
    }
}

static int same_hash(const char *a, const char *b)
{
    size_t n = strlen(a), i;
    unsigned char acc = 0;

    if (n != strlen(b))
        return 0;
    for (i = 0; i < n; i++)
        acc |= (unsigned char)(a[i] ^ b[i]);
    return acc == 0;
}

void ask_password(const struct passwd *pw)
{
    char host[HOST_NAME_MAX + 1], prompt[128], secret[1024];
    const char *h = pw->pw_passwd;
    char *hash, *typed;
    struct spwd *sp;
    int tries;

    if (h && strcmp(h, "x") == 0)
        h = (sp = getspnam(pw->pw_name)) ? sp->sp_pwdp : NULL;
    if (!h || *h == '\0' || *h == '!' || *h == '*')
        errx(1, "no usable password for %s", pw->pw_name);
    if (!(hash = strdup(h)))
        err(1, NULL);

    if (gethostname(host, sizeof(host)) == -1)
        strcpy(host, "?");
    host[sizeof(host) - 1] = '\0';
    snprintf(prompt, sizeof(prompt), "[elev] password for %.32s@%.32s: ",
             pw->pw_name, host);

    for (tries = 1;; tries++) {
        read_secret(prompt, secret, sizeof(secret), pw->pw_name);
        typed = crypt(secret, hash);
        explicit_bzero(secret, sizeof(secret));
        if (typed && same_hash(typed, hash))
            break;
        syslog(LOG_AUTHPRIV | LOG_NOTICE, "bad password user=%s",
               pw->pw_name);
        if (tries == MAX_TRIES)
            errx(1, "too many wrong passwords");
        warnx("wrong password, try again");
    }
    free(hash);
}
