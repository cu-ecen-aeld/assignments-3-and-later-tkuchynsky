.PHONY = clean all

ifdef CROSS_COMPILE
ifneq ($(CROSS_COMPILE), aarch64-none-linux-gnu-)
$(error '$(CROSS_COMPILE)' is not supported!)
endif
endif

CC = $(CROSS_COMPILE)gcc

all: writer

writer: writer.c
	${CC} writer.c -o writer

clean:
	rm -f writer