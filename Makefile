CC   = gcc
CXX  = g++
CFLAGS = -Wall -Werror -march=native -O3
LDFLAGS= -s 

SRC = r3_args.c \
	hmac.c md5.c sha.c gostsum.c

ARCH ?= $(shell uname -m)
ifeq ($(ARCH),aarch64)
SRC += sha256_arm.c

else ifeq ($(ARCH),x86_64) 
#  echo "" | gcc -dM -E -march=native - | grep "__SHA__" 
SRC +=	sha256_ni.c

else 
SRC += sha256.c 
endif

SRC += sha512.c shake256.c stribog.c gosthash.c

OUTPUT=gostsum
INSTALL=gostsum
.PHONY: all clean

all: $(OUTPUT)

$(OUTPUT): $(SRC:.c=.o)
	$(CC) $(LDFLAGS) -o $(OUTPUT) $^

clean:
	rm -f $(OUTPUT) $(SRC:.c=.o)

install: $(OUTPUT)
	@mkdir -p $(INSTALL)
