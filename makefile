PREFIX     = /usr/local
SYSCONFDIR = /etc
SAFE_PATH  = /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

GRACE_OBJ = grace.o
GRACE_DEF = -DELEV_GRACE

CC      = cc
CFLAGS  = -std=c99 -Wall -Wextra -Os
LDFLAGS = -s
LDLIBS  = -lcrypt

DEFS = -DCONF_FILE=\"$(SYSCONFDIR)/elev.conf\" \
       -DSAFE_PATH=\"$(SAFE_PATH)\" $(GRACE_DEF)
OBJS = elev.o ruleset.o childenv.o password.o $(GRACE_OBJ)
BIN  = $(DESTDIR)$(PREFIX)/bin/elev

all: elev

elev: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

.c.o:
	$(CC) $(CFLAGS) $(DEFS) -c $<

$(OBJS): elev.h makefile

install: elev
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp -f elev $(BIN)
	chown root:root $(BIN)
	chmod 4755 $(BIN)

uninstall:
	rm -f $(BIN)

clean:
	rm -f elev *.o

.PHONY: all clean install uninstall
