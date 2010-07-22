CC=gcc
LD=ld
CFLAGS=-I/usr/include/libxml2 -fPIC -Wall
LDFLAGS=-lldap -lcurl -lxml2 -lpam -lconfuse -x --shared
OBJFILES=pam_vip.o
SRCFILES=pam_vip.c
SOFILE=pam_vip.so
CURLVERSION := $(shell curl-config --vernum)

ifeq (${CURLVERSION},070f05)
    CFLAGS += -D OLDCURL
endif

ifeq (${MAKECMDGOALS},debug)
	DEBUG=-ggdb -O0
else
	DEBUG=
endif

all: debug

debug: $(SOFILE) $(OBJFILES)
	
$(SOFILE): $(OBJFILES) 
	$(LD) $(DEBUG) $(LDFLAGS) $(OBJFILES) -o $@

.cpp.o:
	$(CC) $(DEBUG) $(CFLAGS)  $< -o $@

clean:
	rm -f $(SOFILE) $(OBJFILES)
