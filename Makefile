# gostsum — Linux / FreeBSD / MSYS2 (MinGW)
CC   ?= gcc
CFLAGS ?= -std=gnu11 -Wall -O3
LDFLAGS ?= -s

# Linux/macOS: -march=native. MSYS2 Mingw: тоже native CPU гостя.
ifndef NO_NATIVE
CFLAGS += -march=native
endif

# POSIX / MinGW часто ждут _GNU_SOURCE для части прототипов
CFLAGS += -D_GNU_SOURCE

SRC = r3_args.c \
	hmac.c md5.c sha.c gostsum.c

ARCH ?= $(shell uname -m 2>/dev/null || echo unknown)
# MSYS2: MSYSTEM=MINGW64 / UCRT64 / CLANG64
ifdef MSYSTEM
ifeq ($(MSYSTEM),MINGW32)
ARCH := i686
else
ARCH := x86_64
endif
endif

ifeq ($(ARCH),aarch64)
SRC += sha256_arm.c
else ifeq ($(ARCH),arm64)
SRC += sha256_arm.c
else ifeq ($(filter $(ARCH),x86_64 AMD64 amd64),$(ARCH))
SHA_NI := $(shell echo | $(CC) $(CFLAGS) -dM -E - 2>/dev/null | grep -q '__SHA__' && echo 1)
ifeq ($(SHA_NI),1)
SRC += sha256_ni.c
else
SRC += sha256.c
endif
else
SRC += sha256.c
endif

SRC += sha512.c shake256.c stribog.c gosthash.c

OUTPUT = gostsum
ifeq ($(OS),Windows_NT)
OUTPUT := gostsum.exe
endif
ifdef MSYSTEM
OUTPUT := gostsum.exe
endif

.PHONY: all clean check

all: $(OUTPUT)

$(OUTPUT): $(SRC:.c=.o)
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	rm -f $(OUTPUT) $(SRC:.c=.o)

# check: portable temp file (MSYS2 has /tmp; иначе текущий каталог)
check: $(OUTPUT)
	@CHK=gostsum-check-$$$$; printf abc > $$CHK; \
	./$(OUTPUT) -a sha256 $$CHK | grep -qi ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad && \
	./$(OUTPUT) -a gost $$CHK >/dev/null && \
	printf abc | ./$(OUTPUT) -a sha256 - | grep -qi ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad && \
	rm -f $$CHK && echo 'gostsum check: ok'
