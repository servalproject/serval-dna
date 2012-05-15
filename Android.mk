# Included by top-level Android.mk

# Build NACL
include $(CLEAR_VARS)

# Work out where NACL is
NACL_VER=$(shell cat $(LOCAL_PATH)/serval-dna/nacl/nacl-version)
NACL_BASE=serval-dna/nacl/$(NACL_VER)/build_android
NACL_INC=$(LOCAL_PATH)/$(NACL_BASE)

# Find sources
include $(LOCAL_PATH)/$(NACL_BASE)/sources.mk

LOCAL_MODULE:= nacl

LOCAL_SRC_FILES:= $(NACL_SOURCES)

LOCAL_CFLAGS += -I$(NACL_INC) \

include $(BUILD_STATIC_LIBRARY)

# Build DNA
include $(CLEAR_VARS)

# Find SQLITE3 headers
SQLITE3_INC=$(LOCAL_PATH)/sqlite3

# Get the list of sources
include $(LOCAL_PATH)/serval-dna/nacl/$(NACL_VER)/build_android/sources.mk

LOCAL_SRC_FILES:= \
        serval-dna/main.c \
        serval-dna/overlay_abbreviations.c \
	serval-dna/overlay_advertise.c \
	serval-dna/overlay_buffer.c        \
	serval-dna/overlay_interface.c     \
	serval-dna/overlay_packetformats.c \
	serval-dna/overlay_payload.c       \
	serval-dna/overlay_route.c         \
	serval-dna/overlay_mdp.c	\
        serval-dna/batman.c        \
        serval-dna/ciphers.c       \
        serval-dna/client.c        \
	serval-dna/commandline.c   \
        serval-dna/dataformats.c   \
        serval-dna/dna.c           \
        serval-dna/log.c           \
        serval-dna/mkdir.c         \
        serval-dna/gateway.c       \
        serval-dna/overlay.c       \
        serval-dna/overlay_broadcast.c \
        serval-dna/packetformats.c \
        serval-dna/peers.c         \
	serval-dna/randombytes.c \
	serval-dna/rhizome.c \
	serval-dna/rhizome_bundle.c \
	serval-dna/rhizome_crypto.c \
	serval-dna/rhizome_database.c \
	serval-dna/rhizome_fetch.c \
	serval-dna/rhizome_http.c \
	serval-dna/rhizome_packetformats.c \
        serval-dna/responses.c     \
	serval-dna/serval_packetvisualise.c \
        serval-dna/server.c        \
        serval-dna/trans_cache.c   \
	serval-dna/sha2.c          \
	serval-dna/simulate.c      \
        serval-dna/srandomdev.c    \
	serval-dna/keyring.c       \
	serval-dna/vomp.c \
	serval-dna/lsif.c \
	serval-dna/monitor.c \
	serval-dna/monitor-cli.c \
	serval-dna/codecs.c \
	serval-dna/audiodevices.c \
	serval-dna/audio_msm_g1.c \
	serval-dna/audio_alsa.c \
	serval-dna/audio_reflector.c

LOCAL_MODULE:= serval

LOCAL_CFLAGS += \
        -DSHELL -DPACKAGE_NAME=\"\" -DPACKAGE_TARNAME=\"\" -DPACKAGE_VERSION=\"\" \
        -DPACKAGE_STRING=\"\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" \
        -DHAVE_LIBC=1 -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 \
        -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 \
        -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -DHAVE_STDIO_H=1 \
        -DHAVE_ERRNO_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRINGS_H=1 -DHAVE_UNISTD_H=1 \
        -DHAVE_STRING_H=1 -DHAVE_ARPA_INET_H=1 -DHAVE_SYS_SOCKET_H=1 \
        -DHAVE_SYS_MMAN_H=1 -DHAVE_SYS_TIME_H=1 -DHAVE_POLL_H=1 -DHAVE_NETDB_H=1 \
	-DHAVE_JNI_H=1 -DHAVE_STRUCT_UCRED=1 -DBYTE_ORDER=_BYTE_ORDER \
	-I$(NACL_INC) \
	-I$(SQLITE3_INC)
LOCAL_LDLIBS := -L$(SYSROOT)/usr/lib -llog 

LOCAL_STATIC_LIBRARIES := sqlite3 nacl

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_MODULE:= servald
LOCAL_SRC_FILES:= serval-dna/servalwrap.c

include $(BUILD_EXECUTABLE)
