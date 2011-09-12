SRCS=	dna.c server.c client.c peers.c ciphers.c responses.c packetformats.c dataformats.c \
	hlrdata.c srandomdev.c simulate.c batman.c export.c gateway.c \
	overlay.c overlay_buffer.c overlay_interface.c overlay_payload.c overlay_route.c \
	overlay_packetformats.c overlay_abbreviations.c overlay_advertise.c

OBJS=	dna.o server.o client.o peers.o ciphers.o responses.o packetformats.o dataformats.o \
	hlrdata.o srandomdev.o simulate.o batman.o export.o gateway.o \
	overlay.o overlay_buffer.o overlay_interface.o overlay_payload.o overlay_route.o \
	overlay_packetformats.o overlay_abbreviations.o overlay_advertise.o

HDRS=	Makefile mphlr.h
#LDFLAGS=	-L/Developer/SDKs/MacOSX10.6.sdk/usr/lib
#CFLAGS=	-I/Developer/SDKs/MacOSX10.6.sdk/usr/include
#LDFLAGS= -L/opt/local/lib -lefence
DEFS=	-DPACKAGE_NAME=\"\" -DPACKAGE_TARNAME=\"\" -DPACKAGE_VERSION=\"\" -DPACKAGE_STRING=\"\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DHAVE_LIBC=1 -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -DHAVE_STDIO_H=1 -DHAVE_ERRNO_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRINGS_H=1 -DHAVE_UNISTD_H=1 -DHAVE_STRING_H=1 -DHAVE_ARPA_INET_H=1 -DHAVE_SYS_SOCKET_H=1 -DHAVE_SYS_MMAN_H=1 -DHAVE_SYS_TIME_H=1 -DHAVE_POLL_H=1 -DHAVE_NETDB_H=1 -DHAVE_NETINET_IN_H=1 -DHAVE_IFADDRS_H=1

all:	serval.c dna

%.o:	%.c $(HDRS)
	$(CC) $(CFLAGS) $(DEFS) -g -Wall -c $<

dna:	$(OBJS)
	$(CC) $(CFLAGS) -g -Wall -o dna $(OBJS) $(LDFLAGS)

serval.c:	$(SRCS) $(HDRS)
	cat mphlr.h > serval.c
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

testset:	dna testget
	clear
	# Try writing a value to a variable
	echo "short value" >shortvalue.txt
	./dna -vvv -s `cat testget | cut -f2 -d: | tail -1` -i 0 -W note=@shortvalue.txt

testbigset: testget
	clear
	./dna -vvv -s `cat testget | cut -f2 -d: | tail -1` -i 0 -W note=@411.txt
