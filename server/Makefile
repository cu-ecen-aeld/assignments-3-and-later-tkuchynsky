ifdef CROSS_COMPILE
	ifneq ($(CROSS_COMPILE), aarch64-none-linux-gnu-)
		$(error '$(CROSS_COMPILE)' is not supported!)
	endif
	CC = $(CROSS_COMPILE)gcc
endif

# ifneq ($(USE_AESD_CHAR_DEVICE),)
# # call from kernel build system
# CCFLAGS += -DUSE_AESD_CHAR_DEVICE=1
# endif

CC ?= gcc

CCFLAGS += -Wall -Werror -g -DUSE_AESD_CHAR_DEVICE=1

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