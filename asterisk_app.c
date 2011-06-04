/*
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 * 
 * \brief Connect with Serval Distributed Numbering Architecture for Mesh Calling
 *
 * Paul Gardner-Stephen (paul@servalproject.org)
 *
 * \ingroup applications
 */

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision: Serval $")

#include <sys/types.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <pthread.h>


#include "asterisk/utils.h"
#include "asterisk/lock.h"
#include "asterisk/file.h"
#include "asterisk/logger.h"
#include "asterisk/channel.h"
#include "asterisk/callerid.h"
#include "asterisk/pbx.h"
#include "asterisk/module.h"
#include "asterisk/translate.h"
#include "asterisk/features.h"
#include "asterisk/options.h"
#include "asterisk/cli.h"
#include "asterisk/config.h"
#include "asterisk/say.h"
#include "asterisk/localtime.h"
#include "asterisk/cdr.h"
#include "asterisk/options.h"

#include "mphlr.h"

#undef inet_ntoa
#define inet_ntoa ast_inet_ntoa

static char *sdnalookup_descrip = 
  "  SDNALookup(): Resolves a telephone number into SIP address via Serval Distributed Numbering Architecture\n";

static char *sdnalookup_app = "SDNALookup";
static char *sdnalookup_synopsis = "Resolve DID into SIP address via Serval DNA";

//char *gatewayuri=NULL;
//int debug=0;

static char sdnalookup_usage[]=
  "Usage: serval dna lookup <did>\n"
  "       Attempt to resolve a DID into a SIP address via Serval DNA.\n"
  "Examples:\n"
  "       serval dna lookup 0427679796\n";

static char sdnapeers_usage[]=
  "Usage: serval dna peers\n"
  "       Ask DNA to list the peers currently reachable on the mesh.\n"
  "Examples:\n"
  "       serval dna peers\n";

static char sdnadebug_usage[]=
  "Usage: serval debug <debug level>\n"
  "       Set Serval debug level (0-3 are useful values).\n"
  "Examples:\n"
  "       serval debug 3\n";

static char sdnagate_usage[]=
  "Usage: serval dna gateway [gateway uri]\n"
  "       Offer Serval DNA gateway services to allow other BatPhones to use our SIP trunk.\n"
  "Examples:\n"
  "       serval dna gateway 4000@10.130.1.101\n";

static char sdnaaddpeer_usage[]=
  "Usage: serval dna addpeer <peer addr>\n"
  "       Add a static peer to Serval DNA.\n"
  "Examples:\n"
  "       serval dna addpeer 10.20.30.40\n";

static char *handle_cli_sdnalookup(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
  char *did=NULL;
  char *sid=NULL;
  unsigned char buffer[65535];
  int len=0;
  int instance=0;

   switch (cmd) {
   case CLI_INIT:
      e->command = "serval dna lookup";
      e->usage = sdnalookup_usage;
      return NULL;
   case CLI_GENERATE:
      return NULL;
   }

   if (a->argc != 4) {
        ast_cli(a->fd, "You did not provide an argument to serval dna lookup\n\n");
        return RESULT_FAILURE;
    }

   did=a->argv[3];

//   batman_peerfile="/data/data/org.servalproject/var/batmand.peers";

   fprintf(stderr, "batman_peerfile=%s\n", batman_peerfile);
   if (requestItem(did,sid,"locations",instance,buffer,sizeof(buffer),&len,NULL))
     {
       ast_cli(a->fd,"Serval DNA Lookup: requestItem() failed (len=%d).\n\n",len);
       return RESULT_FAILURE;
     }
   
   ast_cli(a->fd,"%s resolves to %s\n",did,buffer);
   return RESULT_SUCCESS;
}

static char *handle_cli_sdnapeers(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
  int i;

   switch (cmd) {
   case CLI_INIT:
      e->command = "serval dna peers";
      e->usage = sdnapeers_usage;
      return NULL;
   case CLI_GENERATE:
      return NULL;
   }
 
   if (a->argc != 3) {
        ast_cli(a->fd, "serval dna peers does not argue about arguments.\n\n");
        return RESULT_FAILURE;
    }

//   batman_peerfile="/data/data/org.servalproject/var/batmand.peers";
   getPeerList();
   ast_cli(a->fd,"%d peers reachable:\n",peer_count);
   for(i=0;i<peer_count;i++)
     {
       unsigned char *c=(unsigned char *)&peers[i];
       ast_cli(a->fd,"  %d.%d.%d.%d\n",c[0],c[1],c[2],c[3]);
     }
   return RESULT_SUCCESS;
}


static char *handle_cli_sdnagate(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
   int len=0;

   switch (cmd) {
   case CLI_INIT:
      e->command = "serval dna gateway";
      e->usage = sdnagate_usage;
      return NULL;
   case CLI_GENERATE:
      return NULL;
   }

   if (gatewayuri) free(gatewayuri);
   gatewayuri=NULL;
   if (a->argc == 3 ) {
       ast_cli(a->fd,"Serval DNA Gateway Function OFF.\n\n",len);
       return RESULT_SUCCESS;
   } 
   if (a->argc != 4) {
        ast_cli(a->fd, "You did not provide an argument to serval dna gateway\n\n");
        return RESULT_FAILURE;
    }

   gatewayuri=strdup(a->argv[3]);

   ast_cli(a->fd,"Serval DNA Gateway Function ON (trunk URI is %s/EXTENSION).\n\n",gatewayuri);
   return RESULT_SUCCESS;
}

static char *handle_cli_sdnadebug(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
   switch (cmd) {
   case CLI_INIT:
      e->command = "serval debug";
      e->usage = sdnadebug_usage;
      return NULL;
   case CLI_GENERATE:
      return NULL;
   }

   if (a->argc != 3) {
        ast_cli(a->fd, "You did not provide an argument to serval debug\n\n");
        return RESULT_FAILURE;
    }

   debug=atoi(a->argv[2]);

   ast_cli(a->fd,"Serval debug level set to %d\n",debug);
   return RESULT_SUCCESS;
}

static char *handle_cli_sdnaaddpeer(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
   switch (cmd) {
   case CLI_INIT:
      e->command = "serval dna addpeer";
      e->usage = sdnaaddpeer_usage;
      return NULL;
   case CLI_GENERATE:
      return NULL;
   }

   if (a->argc != 4) {
        ast_cli(a->fd, "You did not provide an address\n\n");
        return RESULT_FAILURE;
   }

   const char *peer = a->argv[3];

   if (additionalPeer(peer))
       return RESULT_FAILURE;

   ast_cli(a->fd,"Peer %s added successfully\n", peer);
   return RESULT_SUCCESS;
}

static struct ast_cli_entry cli_sdnalookup[] = {
  AST_CLI_DEFINE( handle_cli_sdnalookup, "Resolve a telephone number via Serval DNA" ),
  AST_CLI_DEFINE( handle_cli_sdnapeers, "Ask DNA to list peers reachable on the mesh" ),
  AST_CLI_DEFINE( handle_cli_sdnadebug, "Set Serval debug level" ),
  AST_CLI_DEFINE( handle_cli_sdnagate, "Enable DNA Gateway" ),
  AST_CLI_DEFINE( handle_cli_sdnaaddpeer, "Add a static peer to DNA" )
};

static int sdnalookup_exec(struct ast_channel *chan, void *data)
{
  char *did=data;
  char *sid=NULL;
  unsigned char buffer[65535];
  int len=0;
  int instance=0;

  char status[256] = "INVALIDARGS";

//  batman_peerfile="/data/data/org.servalproject/var/batmand.peers";

  /* Clear Serval DNA set variables */
  pbx_builtin_setvar_helper(chan, "SDNADID", "");
  pbx_builtin_setvar_helper(chan, "SDNASID", "");
  pbx_builtin_setvar_helper(chan, "SDNALOCATION", "");
  pbx_builtin_setvar_helper(chan, "SDNASIG", "");

  if (ast_strlen_zero(data)) {
    ast_log(LOG_WARNING, "SDNALookup requires an argument (number)\n");
    pbx_builtin_setvar_helper(chan, "SDNASTATUS", status);
    if (debug) fprintf(stderr,"SDNASTATUS=%s (a)\n",status);
    return -1;
  }

  /* XXX - Simple version for now.  Should really use a derivation of the core code from the function below to:
     (a) provide more meaningful errors;
     (b) retrieve the SID for the DID for further use
     (c) fetch the voicesig as well if requested 
  */
  if (requestItem(did,sid,"locations",instance,buffer,sizeof(buffer),&len,NULL))
    {
      pbx_builtin_setvar_helper(chan,"SNASTATUS","FAILED");
      if (debug) fprintf(stderr,"SDNASTATUS=FAILED\n");
      return -1;
    }

  /* It worked, so set appropriate variables and return happily */
  pbx_builtin_setvar_helper(chan,"SNADID",did);
  if (debug) fprintf(stderr,"SNADID=%s\n",did);
  if (sid) {
    pbx_builtin_setvar_helper(chan,"SNASID",sid);
    if (debug) fprintf(stderr,"SNASID=%s\n",sid);
  }
  if (len) {
    pbx_builtin_setvar_helper(chan,"SDNALOCATION",(char*)buffer);
    if (debug) fprintf(stderr,"SNALOCATION=%s\n",buffer);
  }
  return 0;
}

static int unload_module(void)
{
  int res;

  ast_cli_unregister_multiple(cli_sdnalookup, ARRAY_LEN(cli_sdnalookup));
  res = ast_unregister_application(sdnalookup_app);

  return res;
}

static int load_module(void)
{
  batman_peerfile=NULL;
  ast_cli_register_multiple(cli_sdnalookup, ARRAY_LEN(cli_sdnalookup));
  ast_register_application(sdnalookup_app, sdnalookup_exec, sdnalookup_synopsis, sdnalookup_descrip);
#ifdef ASTERISK_1_4
  return AST_MODULE_LOAD_SUCCESS;
#else
  return 0;
#endif
}

#define AST_MODULE "app_serval"

AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "Serval Mesh Telephony Adapter and Serval DNA Resolver");
