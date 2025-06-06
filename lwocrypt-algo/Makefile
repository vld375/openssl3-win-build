TARGET = libcrypt-algo.a
CC	= gcc
CFLAGS	=  -Wall -O3 -pthread
LIBFLAG	= -fPIC -fpic

LIBINC = -I./ -I../include -I/usr/include
CCOPTS  = -g $(LIBINC) 
OBJDIR  = ./obj
LIBDIR  = ./../lib
LDOPTSO	= -L/usr/lib/x86_64-linux-gnu 
LDOPTSO += -ldl
LDOPTSO += -lc
LDOPTSO += -lcrypto -Wl,--soname,$@

INCLUDES = belt/belt_local.h brng/brng_local.h ../include/lwocrypt/bash.h ../include/lwocrypt/belt.h ../include/lwocrypt/brng.h 

COURCE = bash/bash_dgst.o bash/bash_one.o \
	 belt/belt_add.o belt/belt_bde.o belt/belt_cbc.o belt/belt_cfb.o belt/belt_ctr.o belt/belt_dgst.o \
	 belt/belt_dwp.o belt/belt_ecb.o belt/belt_kwp.o belt/belt_mac.o belt/belt_sde.o \
	 brng/brng_ctr_hbelt.o brng/hmac_hbelt.o 

OBJECTS = bash_dgst.o bash_one.o \
	  belt_add.o belt_bde.o belt_cbc.o belt_cfb.o belt_ctr.o belt_dgst.o \
	  belt_dwp.o belt_ecb.o belt_kwp.o belt_mac.o belt_sde.o \
	  brng_ctr_hbelt.o hmac_hbelt.o 

RM = rm -f
CP = cp

all:  $(COURCE) $(LIBDIR)/$(TARGET) clean

clean: 
	$(RM) $(OBJECTS)

install: 
	$(CP) $(LIBDIR)/$(TARGET) /usr/lib/x86_64-linux-gnu/ossl-modules

$(LIBDIR)/$(TARGET): 		$(OBJECTS)
				ar r $@ $?					

%.o: %.c $(INCLUDES)
	$(CC) $(CFLAGS) $(LIBFLAG) $(LIBINC) -c $<





