ifdef CROSS_COMPILE
	ifneq ($(CROSS_COMPILE), aarch64-none-linux-gnu-)
		$(error '$(CROSS_COMPILE)' is not supported!)
	endif
	CC = $(CROSS_COMPILE)gcc
endif

CC ?= gcc

CCFLAGS += -Wall -Werror -g

.PHONY = default
default: all

.PHONY = all
all: aesdsocket

aesdsocket.o: aesdsocket.c
	$(CC) $(CCFLAGS) -c aesdsocket.c

aesdsocket: aesdsocket.o
	${CC} ${LDFLAGS} -pthread aesdsocket.o -o aesdsocket

.PHONY = clean 
clean:
	rm -f aesdsocket aesdsocket.o