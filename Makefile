SRCS=	batman.c \
	ciphers.c \
	client.c \
	commandline.c \
	dataformats.c \
	dna.c \
	export.c \
	gateway.c \
	hlrdata.c \
	overlay.c \
	overlay_abbreviations.c \
	overlay_advertise.c \
	overlay_broadcast.c \
	overlay_buffer.c \
	overlay_interface.c \
	overlay_packetformats.c \
	overlay_payload.c \
	overlay_route.c \
	packetformats.c \
	peers.c \
	randombytes.c \
	responses.c \
	rhizome.c \
	rhizome_bundle.c \
	rhizome_crypto.c \
	rhizome_database.c \
	rhizome_fetch.c \
	rhizome_http.c \
	rhizome_packetformats.c \
	serval_packetvisualise.c \
	server.c \
	sha2.c \
	simulate.c \
	srandomdev.c

OBJS=	$(SRCS:.c=.o)

HDRS=	Makefile serval.h

# NACL library build info
# You must run the following for this to work
# cd nacl-20110221
# ../nacl-gcc-prep
NACL_CFLAGS=-Inacl/$(shell cat nacl/naclinc.txt)
NACL_LDFLAGS=nacl/$(shell cat nacl/nacllib.txt)

# SQLITE3 build info
SQLITE3_CFLAGS=$(shell pkg-config --cflags sqlite3)
SQLITE3_LDFLAGS=$(shell pkg-config --libs sqlite3)

LDFLAGS=$(NACL_LDFLAGS) $(SQLITE3_LDFLAGS)
CFLAGS=	-g -O2 $(NACL_CFLAGS) $(SQLITE3_CFLAGS)

DEFS=	-DPACKAGE_NAME=\"\" -DPACKAGE_TARNAME=\"\" -DPACKAGE_VERSION=\"\" -DPACKAGE_STRING=\"\" -DPACKAGE_BUGREPORT=\"\" -DHAVE_LIBC=1 -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -DHAVE_STDIO_H=1 -DHAVE_ERRNO_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRINGS_H=1 -DHAVE_UNISTD_H=1 -DHAVE_STRING_H=1 -DHAVE_ARPA_INET_H=1 -DHAVE_SYS_SOCKET_H=1 -DHAVE_SYS_MMAN_H=1 -DHAVE_SYS_TIME_H=1 -DHAVE_POLL_H=1 -DHAVE_NETDB_H=1 -DHAVE_NET_IF_H=1 -DHAVE_NETINET_IN_H=1 -DHAVE_IFADDRS_H=1 -DHAVE_NET_ROUTE_H=1

all:	dna serval.c

%.o:	%.c $(HDRS)
	$(CC) $(CFLAGS) $(DEFS) -Os -g -Wall -c $<

dna:	$(OBJS)
	$(CC) $(CFLAGS) -Os -g -Wall -o dna $(OBJS) $(LDFLAGS)

serval.c:	$(SRCS) $(HDRS)
	cat serval.h > serval.c
	echo '#include <sys/mman.h>' >>serval.c
	cat $(SRCS) | grep -v "#include" | sed -e 's/inet_ntoa/ast_inet_ntoa/g' >>serval.c

testserver: dna
	clear
	rm hlr.dat
	./dna -vvv -S 1 -f hlr.dat

testcreate: dna
	clear
	./dna -vvv -d 0427679796 -C
	@touch testcreate

testget:	dna testcreate
	clear
	./dna -vvv -d 0427679796 -R dids | tee testget

# Try writing a value to a variable
testset:	dna testget
	clear
	echo "short value" >shortvalue.txt
	./dna -vvv -s `cat testget | cut -f2 -d: | tail -1` -i 0 -W note=@shortvalue.txt

testbigset: testget
	clear
	./dna -vvv -s `cat testget | cut -f2 -d: | tail -1` -i 0 -W note=@411.txt

clean:
	rm -f dna $(OBJS)

