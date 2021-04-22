# PKG_CONFIG_PATH=C:\GTK\lib\pkgconfig
CC   = gcc
CFLAGS = -Wall -Werror -march=native -O3
LDFLAGS= -s 
# -g3
# -lsocket

SRC = r3_args.c \
	hmac.c md5.c sha.c sha512.c stribog.c gostsum.c gosthash.c

OUTPUT=gostsum
INSTALL=gostsum
.PHONY: all clean

all: $(OUTPUT)

$(OUTPUT): $(SRC:.c=.o)
	$(CC) $(LDFLAGS) -o $(OUTPUT) $^

clean:
	rm -f $(OUTPUT) $(SRC:.c=.o)

# cp ../r2test/r3test $(INSTALL)/

install: $(OUTPUT)
	@mkdir -p $(INSTALL)
