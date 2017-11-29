/*
 Serval testing command line functions
 Copyright (C) 2014 Serval Project Inc.
 
 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either version 2
 of the License, or (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>

#include "cli.h"
#include "serval_types.h"
#include "dataformats.h"
#include "os.h"
#include "conf.h"
#include "commandline.h"
#include "mem.h"
#include "str.h"

DEFINE_FEATURE(cli_tests);

DEFINE_CMD(app_byteorder_test, 0,
  "Run byte order handling test",
  "test","byteorder");
static int app_byteorder_test(const struct cli_parsed *UNUSED(parsed), struct cli_context *UNUSED(context))
{
  uint64_t in=0x1234;
  uint64_t out;

  unsigned char bytes[8];

  write_uint64(&bytes[0],in);
  out=read_uint64(&bytes[0]);
  if (in!=out)
    cli_printf(context,"Byte order mangled (0x%016"PRIx64" should have been %016"PRIx64")\n",
	       out,in);
  else cli_printf(context,"Byte order preserved.\n");
  return -1;
}

DEFINE_CMD(app_crypt_test, 0,
   "Run cryptography speed test",
   "test","crypt");
static int app_crypt_test(const struct cli_parsed *parsed, struct cli_context *context)
{
  DEBUG_cli_parsed(verbose, parsed);
  unsigned char nonce[crypto_box_curve25519xsalsa20poly1305_NONCEBYTES];
  unsigned char k[crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES];

  unsigned char plain_block[65536];

  randombytes_buf(nonce,sizeof(nonce));
  randombytes_buf(k,sizeof(k));

  int len,i;

  cli_printf(context, "Benchmarking CryptoBox Auth-Cryption:\n");
  int count=1024;
  for(len=16;len<=16384;len*=2) {
    time_ms_t start = gettime_ms();
    for (i=0;i<count;i++) {
      bzero(&plain_block[0],crypto_box_curve25519xsalsa20poly1305_ZEROBYTES);
      crypto_box_curve25519xsalsa20poly1305_afternm
	(plain_block,plain_block,len,nonce,k);
    }
    time_ms_t end = gettime_ms();
    double each=(end - start) * 1.0 / i;
    cli_printf(context, "%d bytes - %d tests took %"PRId64"ms - mean time = %.2fms\n",
	   len, i, (int64_t)(end - start), each);
    /* Auto-reduce number of repeats so that it doesn't take too long on the phone */
    if (each>1.00) count/=2;
  }


  cli_printf(context, "Benchmarking CryptoSign signature verification:\n");
  {

    unsigned char sign_pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sign_sk[crypto_sign_SECRETKEYBYTES];
    if (crypto_sign_keypair(sign_pk,sign_sk))
      return WHY("crypto_sign_keypair() failed.\n");

    unsigned char plainText[1024];
    unsigned char sig[crypto_sign_BYTES];
    bzero(plainText,sizeof plainText);
    snprintf((char *)&plainText[0],sizeof plainText,"%s","No casaba melons allowed in the lab.");
    int plainLenIn=64;

    time_ms_t start = gettime_ms();
    for(i=0;i<10;i++) {
      if (crypto_sign_detached(sig, NULL, plainText, plainLenIn, sign_sk))
        return WHY("crypto_sign_detached() failed.\n");
    }

    time_ms_t end=gettime_ms();
    cli_printf(context, "mean signature generation time = %.2fms\n",
  	   (end-start)*1.0/i);
    start = gettime_ms();

    for(i=0;i<10;i++) {
      if (crypto_sign_verify_detached(sig, plainText, plainLenIn, sign_pk))
	return WHYF("crypto_sign_verify_detached() failed (i=%d).\n",i);
    }
    end = gettime_ms();
    cli_printf(context, "mean signature verification time = %.2fms\n",
	   (end-start)*1.0/i);
  }

  /* We can't do public signing with a crypto_box key, but we should be able to
     do shared-secret generation using crypto_sign keys. */
  {
    cli_printf(context, "Verifying CryptoSign implementation:\n");

    unsigned char sign1_pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sign1_sk[crypto_sign_SECRETKEYBYTES];
    if (crypto_sign_keypair(sign1_pk,sign1_sk))
      return WHY("crypto_sign_keypair() failed.\n");

    /* Try calculating public key from secret key */
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];

    if (memcmp(&sign1_sk[32], sign1_pk, crypto_sign_PUBLICKEYBYTES)) {
      WHY("Could not calculate public key from private key.\n");
      WHY_dump("calculated",&pk,sizeof(pk));
      WHY_dump("original",&sign1_pk,sizeof(sign1_pk));
    } else
      cli_printf(context, "Public key is contained in private key.\n");

    /* Now use a pre-tested keypair and make sure that we can sign and verify with
       it, and that the signatures are as expected. */
    
    unsigned char key[crypto_sign_SECRETKEYBYTES]={
      0xf6,0x70,0x6b,0x8a,0x4e,0x1e,0x4b,0x01,
      0x11,0x56,0x85,0xac,0x63,0x46,0x67,0x5f,
      0xc1,0x44,0xcf,0xdf,0x98,0x5c,0x2b,0x8b,
      0x18,0xff,0x70,0x9c,0x12,0x71,0x48,0xb9,

      0x32,0x2a,0x88,0xba,0x9c,0xdd,0xed,0x35,
      0x8f,0x01,0x18,0xf7,0x60,0x1b,0xfb,0x80,
      0xaf,0xce,0x74,0xe0,0x85,0x39,0xac,0x13,
      0x15,0xf6,0x79,0xaa,0x68,0xef,0x5d,0xc6};

    unsigned char plainText[1024];
    unsigned char sig[crypto_sign_BYTES];
    bzero(plainText,1024);
    snprintf((char *)&plainText[0],sizeof plainText,"%s","No casaba melons allowed in the lab.");
    int plainLenIn=64;
    WHY_dump("plaintext", plainText, 64);

    if (crypto_sign_detached(sig, NULL, plainText, plainLenIn, key))
      return WHY("crypto_sign_detached() failed.\n");
  
    WHY_dump("signature", sig, sizeof sig);
   
    unsigned char casabamelons[crypto_sign_BYTES]={
      0xa4,0xea,0xd0,0x7f,0x11,0x65,0x28,0x3f,
      0x90,0x45,0x87,0xbf,0xe5,0xb9,0x15,0x2a,
      0x9a,0x2d,0x99,0x35,0x0d,0x0e,0x7b,0xb0,
      0xcd,0x15,0x2e,0xe8,0xeb,0xb3,0xc2,0xb1,
      0x13,0x8e,0xe3,0x82,0x55,0x6c,0x6e,0x34,
      0x44,0xe4,0xbc,0xa3,0xd5,0xe0,0x7a,0x6a,
      0x67,0x61,0xda,0x79,0x67,0xb6,0x1c,0x2e,
      0x48,0xc7,0x28,0x5b,0xd8,0xd0,0x54,0x0c,
    };
    
    if (memcmp(casabamelons, sig, 64)) {
      WHY("Computed signature for stored key+message does not match expected value.\n");
      WHY_dump("expected signature",casabamelons,sizeof(casabamelons));
    }

    if (crypto_sign_verify_detached(sig, plainText, plainLenIn, &key[32]))
      WHY("Cannot open rearranged ref/ version of signature.\n");
    else
      cli_printf(context, "Signature open fine.\n");

  }
  
  return 0;
}

void context_switch_test(int);
DEFINE_CMD(app_mem_test, 0,
   "Run memory speed test",
   "test","memory");
static int app_mem_test(const struct cli_parsed *UNUSED(parsed), struct cli_context *UNUSED(context))
{
  size_t mem_size;
  size_t addr;
  uint64_t count;


  // First test context switch speed
  context_switch_test(1);

  for(mem_size=1024;mem_size<=(128*1024*1024);mem_size*=2) {
    uint8_t *mem=malloc(mem_size);
    if (!mem) {
      fprintf(stderr,"Could not allocate %zdKB memory -- stopping test.\n",mem_size/1024);
      return -1;
    }

    // Fill memory with random stuff so that we don't have memory page-in
    // delays when doing the reads
    for(addr=0;addr<mem_size;addr++) mem[addr]=random()&0xff;
    
    time_ms_t end_time=gettime_ms()+100;
    uint64_t total=0;
    size_t mem_mask=mem_size-1;

    for(count=0;gettime_ms()<end_time;count++) {
      addr=random()&mem_mask;
      total+=mem[addr];
    }
    printf("Memory size = %8zdKB : %"PRId64" random  reads per second (irrelevant sum is %016"PRIx64")\n",
	   mem_size/1024,count*10,
	   /* use total so that compiler doesn't optimise away our memory accesses */
	   total);

    end_time=gettime_ms()+100;
    for(count=0;gettime_ms()<end_time;count++) {
      addr=random()&mem_mask;
      mem[addr]=3;
    }
    printf("Memory size = %8zdKB : %"PRId64" random writes per second (irrelevant sum is %016"PRIx64")\n",
	   mem_size/1024,count*10,
	   /* use total so that compiler doesn't optimise away our memory accesses */
	   total);


    free(mem);
  }

  return 0;
}

DEFINE_CMD(app_config_test, 0,
   "Load a test config file and log various fields",
   "config","test","<file>");
static int app_config_test(const struct cli_parsed *UNUSED(parsed), struct cli_context *UNUSED(context))
{
  const char *filename;
  if (cli_arg(parsed, "file", &filename, NULL, NULL)==-1)
    return -1;

  int fd = open(filename, O_RDONLY);
  if (fd == -1)
    return WHY_perror("open");
  struct stat st;
  fstat(fd, &st);
  char *buf = emalloc(st.st_size);
  if (!buf)
    return -1;
  if (read(fd, buf, st.st_size) != st.st_size)
    return WHY_perror("read");
  struct cf_om_node *root = NULL;
  int ret = cf_om_parse(filename, buf, st.st_size, &root);
  close(fd);
  DEBUGF(verbose, "ret = %s", strbuf_str(strbuf_cf_flags(strbuf_alloca(128), ret)));
  //cf_dump_node(root, 0);
  struct config_main config;
  memset(&config, 0, sizeof config);
  cf_dfl_config_main(&config);
  int result = root ? cf_opt_config_main(&config, root) : CFEMPTY;
  cf_om_free_node(&root);
  free(buf);
  DEBUGF(verbose, "result = %s", strbuf_str(strbuf_cf_flags(strbuf_alloca(128), result)));
  DEBUGF(verbose, "config.log.file.path = %s", alloca_str_toprint(config.log.file.path));
  DEBUGF(verbose, "config.log.file.show_pid = %d", config.log.file.show_pid);
  DEBUGF(verbose, "config.log.file.show_time = %d", config.log.file.show_time);
  DEBUGF(verbose, "config.server.chdir = %s", alloca_str_toprint(config.server.chdir));
  DEBUGF(verbose, "config.debug.verbose = %d", config.debug.verbose);
  DEBUGF(verbose, "config.directory.service = %s", alloca_tohex_sid_t(config.directory.service));
  DEBUGF(verbose, "config.rhizome.api.addfile.allow_host = %s", inet_ntoa(config.rhizome.api.addfile.allow_host));
  unsigned j;
  for (j = 0; j < config.dna.helper.argv.ac; ++j) {
    DEBUGF(verbose, "config.dna.helper.argv.%u=%s", config.dna.helper.argv.av[j].key, config.dna.helper.argv.av[j].value);
  }
  for (j = 0; j < config.rhizome.direct.peer.ac; ++j) {
    DEBUGF(verbose, "config.rhizome.direct.peer.%s", config.rhizome.direct.peer.av[j].key);
    DEBUGF(verbose, "   .protocol = %s", alloca_str_toprint(config.rhizome.direct.peer.av[j].value.protocol));
    DEBUGF(verbose, "   .host = %s", alloca_str_toprint(config.rhizome.direct.peer.av[j].value.host));
    DEBUGF(verbose, "   .port = %u", config.rhizome.direct.peer.av[j].value.port);
  }
  for (j = 0; j < config.interfaces.ac; ++j) {
    DEBUGF(verbose, "config.interfaces.%u", config.interfaces.av[j].key);
    DEBUGF(verbose, "   .exclude = %d", config.interfaces.av[j].value.exclude);
    DEBUGF(verbose, "   .match = [");
    unsigned k;
    for (k = 0; k < config.interfaces.av[j].value.match.patc; ++k)
      DEBUGF(verbose, "             %s", alloca_str_toprint(config.interfaces.av[j].value.match.patv[k]));
    DEBUGF(verbose, "            ]");
    DEBUGF(verbose, "   .type = %d", config.interfaces.av[j].value.type);
    DEBUGF(verbose, "   .port = %u", config.interfaces.av[j].value.port);
    DEBUGF(verbose, "   .broadcast.drop = %d", (int) config.interfaces.av[j].value.broadcast.drop);
    DEBUGF(verbose, "   .unicast.drop = %d", (int) config.interfaces.av[j].value.unicast.drop);
    DEBUGF(verbose, "   .drop_packets = %u", (unsigned) config.interfaces.av[j].value.drop_packets);
  }
  for (j = 0; j < config.hosts.ac; ++j) {
    char sidhex[SID_STRLEN + 1];
    tohex(sidhex, SID_STRLEN, config.hosts.av[j].key.binary);
    DEBUGF(verbose, "config.hosts.%s", sidhex);
    DEBUGF(verbose, "   .interface = %s", alloca_str_toprint(config.hosts.av[j].value.interface));
    DEBUGF(verbose, "   .address = %s", inet_ntoa(config.hosts.av[j].value.address));
    DEBUGF(verbose, "   .port = %u", config.hosts.av[j].value.port);
  }
  return 0;
}
