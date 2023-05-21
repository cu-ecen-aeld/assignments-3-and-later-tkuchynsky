.PHONY = clean all

ifdef CROSS_COMPILE
ifneq ($(CROSS_COMPILE), aarch64-none-linux-gnu-)
$(error '$(CROSS_COMPILE)' is not supported!)
endif
endif

CC = $(CROSS_COMPILE)gcc
CFLAGS= -Wall -Werror -g
.PHONY: default
default: all

all: aesdsocket

aesdsocket: aesdsocket.c
	${CC} ${CFLAGS} -pthread aesdsocket.c -o aesdsocket

clean:
	rm -f aesdsocket