# Компилятор и опции компиляции
CC := gcc
CFLAGS := -Wall -Wextra -I./ -I../include -Iinclude -I../include/providers/implementations/include -I../include/providers/common/include

# Линковщик и опции линковки
LD := gcc

# Исходные файлы
SRCS := common/bio_prov.c common/digest_to_nid.c common/provider_ctx.c common/provider_err.c \
        common/provider_seeding.c common/provider_util.c common/securitycheck.c \
        common/securitycheck_default.c crypto/params_dup.c crypto/param_build.c \
        crypto/param_build_set.c implementations/digests/bash_prov.c implementations/digests/belt_prov.c \
        implementations/digests/digestcommon.c implementations/macs/mac_prov.c \
        implementations/ciphers/cipher_belt.c \
         lwocrypt-prov.c prov_running.c

# Получение имен объектных файлов из исходных файлов
OBJS := $(SRCS:.c=.o)

STATICLIB=/usr/lib/x86_64-linux-gnu/ossl-modules/libcrypt-algo.a

# Имя выходной библиотеки
LIBRARY := liblwocrypt.so

.PHONY: all clean

all: $(LIBRARY)

# Правило для сборки объектных файлов
%.o: %.c
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

# Правило для сборки библиотеки
$(LIBRARY): $(OBJS)
	$(LD) -shared $(OBJS) -o $@ $(STATICLIB)

clean:
	rm -f $(OBJS) $(LIBRARY)