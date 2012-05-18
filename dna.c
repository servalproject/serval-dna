/* 
Serval Distributed Numbering Architecture (DNA)
Copyright (C) 2010 Paul Gardner-Stephen 

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

#include "serval.h"
#include "rhizome.h"
#include <unistd.h>

int usage(char *complaint)
{
  fprintf(stderr,"dna: %s\n",complaint);
  fprintf(stderr,"usage:\n");
  fprintf(stderr,"   dna [-v <flags>] -S [-f keyring file] [-N interface,...] [-G gateway specification] [-r rhizome path]\n");
  fprintf(stderr,"or\n");
  fprintf(stderr,"   dna -r <rhizome path> -M <manifest name>\n");
  fprintf(stderr,"or\n");
  fprintf(stderr,"   dna <-d|-s> id -A\n");
  fprintf(stderr,"or\n");
  fprintf(stderr,"   dna <-d|-s> id [-p pin] [-i variable instance] <-R variable[=value]>\n");
  fprintf(stderr,"       [-v <flags>] [-t request timeout in ms] [-O output file name template]\n");
  fprintf(stderr,"or\n");
  fprintf(stderr,"   dna <-d|-s> id [-p pin] [-i variable instance] <-W|-U|-D variable[=[$|@]value]>\n");
  fprintf(stderr,"       [-v <flags>] [-t request timeout in ms]\n");
  fprintf(stderr,"or\n");
  fprintf(stderr,"   dna [-v <flags>] [-t timeout] -d did -C\n");
  fprintf(stderr,"or\n");
  fprintf(stderr,"   dna [-v <flags>] -f <keyring file> -E <export.txt>\n");

  fprintf(stderr,"\n");
  fprintf(stderr,"       -v - Set verbosity.\n");
  fprintf(stderr,"       -A - Ask for address of subscriber.\n");
  fprintf(stderr,"       -b - Specify BATMAN socket to obtain peer list (flaky).\n");
  fprintf(stderr,"       -l - Specify BATMAN socket to obtain peer list (better, but requires Serval patched BATMAN).\n");
  fprintf(stderr,"       -L - Log mesh statistics to specified file.\n");
  fprintf(stderr,"       -m - Return multiple variable values instead of only first response.\n");
  fprintf(stderr,"       -M - Create and import a new bundle from the specified manifest.\n");
  fprintf(stderr,"       -n - Do not detach from foreground in server mode.\n");
  fprintf(stderr,"       -S - Run in server mode.\n");
  fprintf(stderr,"       -f - Location of keyring file.\n");
  fprintf(stderr,"       -d - Search by Direct Inward Dial (DID) number.\n");
  fprintf(stderr,"       -s - Search by Subscriber ID (SID) number.\n");
  fprintf(stderr,"       -p - Specify additional DNA nodes to query.\n");
  fprintf(stderr,"       -P - Authenticate using the supplied pin.\n");
  fprintf(stderr,"       -r - Enable Rhizome store-and-forward transport using the specified data store directory.\n");
  fprintf(stderr,"            To limit the storage: echo space=[KB] > path/rhizome.conf\n");
  fprintf(stderr,"       -R - Read a variable value.\n");
  fprintf(stderr,"       -O - Place read variable value into files using argument as a template.\n");
  fprintf(stderr,"            The following template codes can be used (interpretted by sprintf):\n");
  fprintf(stderr,"               %%1$s - Subscriber ID\n");
  fprintf(stderr,"               %%2$d - Variable ID (0-255)\n");
  fprintf(stderr,"               %%3$d - Variable instance number (0-255)\n");
  fprintf(stderr,"       -W - Write a variable value, keeping previous values.\n");
  fprintf(stderr,"       -U - Update a variable value, replacing the previous value.\n");
  fprintf(stderr,"       -D - Delete a variable value.\n");
  fprintf(stderr,"            $value means interpret value as hexidecimal bytes.\n");
  fprintf(stderr,"            @value means read value from file called value.\n");
  fprintf(stderr,"       -C - Request the creation of a new subscriber with the specified DID.\n");
  fprintf(stderr,"       -t - Specify the request timeout period.\n");
  fprintf(stderr,"       -G - Offer gateway services.  Argument specifies locations of necessary files.\n");
  fprintf(stderr,"            Use -G [potato|android|custom:...] to set defaults for your device type.\n");
  fprintf(stderr,"       -N - Specify one or more interfaces for the DNA overlay mesh to operate.\n");
  fprintf(stderr,"            Interface specifications take the form <+|->[interface[=type][,...]\n");
  fprintf(stderr,"            e.g., -N -en0,+ to use all interfaces except en0\n");
  fprintf(stderr,"\n");
  exit(-1);
}

int parseOldCommandLine(int argc, char **argv)
{
  int c;
  //char *pin=NULL;
  char *did=NULL;
  char *sid=NULL;
  char *keyring_file=NULL;
  int instance=-1;
  int foregroundMode=0;
  int clientMode=0;
  const char *rhizome_path = NULL;
  WARNF("The use of the old command line structure is being deprecated.");
  WARNF("Type '%s help' to learn about the new command line structure.", argv[0]);
  while ((c = getopt(argc,argv,"Ab:B:E:G:I:Sf:d:i:l:L:mnp:P:r:s:t:v:R:W:U:D:CO:M:N:")) != -1) {
      switch(c)
	{
	case 'S': serverMode=1; break;
	case 'r': /* Enable rhizome */
	  if (rhizome_path) return WHY("-r specified more than once");
	  rhizome_path = optarg;
	  break;
	case 'M': /* Distribute specified manifest and file pair using Rhizome. */
	  /* This option assumes that the manifest is locally produced, and will
	     create any appropriate signatures, replacing any old signatures on the
	     manifest.
	     A different calling would be required to import an existing pre-signed
	     manifest */
	  return rhizome_bundle_import(NULL, NULL, optarg,
				       NULL /* no groups - XXX should allow them */,
				       255 /* ttl - XXX should read from somewhere,
					      e.g., bar if being imported */,
				       0 /* int verifyP */, 
				       1 /* int checkFileP */, 
				       1 /* int signP */);
	  break;
	case 'm': returnMultiVars=1; break;
	case 'N': /* Ask for overlay network to setup one or more interfaces */
	  if (overlay_interface_args(optarg))
	    return WHY("Invalid interface specification(s) passed to -N");
	  overlayMode=1;
	  break;
	case 'G': /* Offer gateway services */
	  gatewayspec=strdup(optarg);
	  if(prepareGateway(gatewayspec)) return usage("Invalid gateway specification");
	  break;
	case 'n': /* don't detach from foreground in server mode */
	  foregroundMode=1; break;
	case 'b': /* talk peers on a BATMAN mesh */
	  batman_socket=strdup(optarg);
	  break;
	case 'l': /* talk peers on a BATMAN mesh */
	  batman_peerfile=strdup(optarg);
	  break;
	case 'L':
	  instrumentation_file=strdup(optarg);
	  break;
	case 'B': /* Set simulated Bit Error Rate for bench-testing */
	  simulatedBER=atof(optarg);
	  fprintf(stderr,"WARNING: Bit error injection enabled -- this will cause packet loss and is intended only for testing.\n");
	  break;
	case 'i':
	  instance=atoi(optarg);
	  if (instance<-1||instance>255) usage("Illegal variable instance ID.");
	  break;
	case 'f':
	  if (clientMode) usage("Only servers use keyring files");
	  keyring_file=strdup(optarg);
	  break;
	case 'p': /* additional peers to query */
	  if (additionalPeer(optarg)) exit(-3);
	  break;
	case 'P': /* Supply pin */
	  //pin=strdup(optarg);
	  clientMode=1;
	  break;
	case 'd': /* Ask by DID */
	  clientMode=1;
	  did=strdup(optarg);
	  break;
	case 's': /* Ask by subscriber ID */
	  clientMode=1;
	  sid=strdup(optarg);
	  break;
	case 't': /* request timeout (ms) */
	  timeout=atoi(optarg);
	  break;
	case 'v': /* set verbosity */
	  debug |= debugFlagMask(optarg);
	  break;
	case 'A': /* get address (IP or otherwise) of a given peer */
	  peerAddress(did,sid,3 /* 1 = print list of addresses to stdout, 2 = set peer list to responders */);
	  break;
	case 'R': /* read a variable */
	  {	    
	    unsigned char buffer[65535];
	    int len=0;
	    requestItem(did,sid,(char *)optarg,instance,buffer,sizeof(buffer),&len,NULL);
	  }
	  break;
	case 'W': /* write a variable */
	  {	    
	    int var_id;
	    unsigned char value[65536];
	    int value_len=65535;
	    if (parseAssignment((unsigned char *)optarg,&var_id,value,&value_len)) return -1;
	    value[value_len]=0;
	    return writeItem(did?did:sid,var_id,instance,value,0,value_len,SET_NOREPLACE,-1,NULL);
	  }
	  break;
	case 'U': /* write or update a variable */
	  {	    
	    int var_id;
	    unsigned char value[65536];
	    int value_len=65535;
	    if (parseAssignment((unsigned char *)optarg,&var_id,value,&value_len)) return -1;
	    value[value_len]=0;
	    return writeItem(did?did:sid,var_id,instance,value,0,value_len,SET_REPLACE,-1,NULL);
	  }
	  break;
	case 'C': /* create a new keyring entry */
	  return WHY("Entries in new keyring format must be used with new command line framework.");
	  break;
	case 'O': /* output to templated files */
	  if (outputtemplate) usage("You can only specify -O once");
	  outputtemplate=strdup(optarg);
	  break;
	default:
	  usage("Invalid option");
	  break;
	}
    }

  if (optind<argc) usage("Extraneous options at end of command");

  if (keyring_file&&clientMode) usage("Only servers use backing files");
  if (serverMode&&clientMode) usage("You asked me to be both server and client.  That's silly.");
  if (rhizome_path) {
    rhizome_set_datastore_path(rhizome_path);
    if (rhizome_opendb() == -1)
      exit(-1);
  }
  if (serverMode) {
    if (!keyring_file) {
      /* Set keyring file to be in the Rhizome directory, to save the need to specify it separately. */
      char temp[1024];
      if (!FORM_RHIZOME_DATASTORE_PATH(temp, "serval.keyring"))
	exit(-1);
      keyring_file = strdup(temp);
    }
    if (!foregroundMode)
      daemon(0,0);
    return server(keyring_file);
  }
  if (!clientMode) usage("Serval server and client utility.");

  /* Client mode: */
  return 0;
}

int parseAssignment(unsigned char *text,int *var_id,unsigned char *value,int *value_len)
{
  /* Parse an assignment.

     Valid formats are:

     var=@file   - value comes from named file.
     var=[[$]value] - value comes from string, and may be empty.  $ means value is in hex

     Values are length limited to 65535 bytes.
  */

  int i;
  int max_len=*value_len;
  int vlen=0;
  int tlen=strlen((char *)text);

  if (tlen>3072) {
    return setReason("Variable assignment string is too long, use =@file to read value from a file");
  }

  /* Identify which variable */
  *var_id=-1;
  for(i=0;i<tlen;i++) if (text[i]=='=') break;
  
  /* Go through known keyring variables */
  if (!strcasecmp((char *)text,"did")) *var_id=KEYTYPE_DID;

  if (*var_id==-1) return setReason("Illegal variable name in assignment");

  i++;
  switch(text[i])
    {
    case '$': /* hex */
      i++;
      while(i<tlen) {
	int b=hexvalue(text[i++])<<4;
	if (i>=tlen) return setReason("Variable value has an odd number of hex digits.");
	b|=hexvalue(text[i++]);
	if (b<0) return setReason("That doesn't look like hex to me");
	if (vlen>=max_len) return setReason("Variable hex value too long");
	value[vlen++]=b;
      }
      *value_len=vlen;
      return 0;
      break;
    case '@': /* file */
      {
	FILE *f=fopen((char *)&text[i+1],"r");
	int flen;
	fseek(f,0,SEEK_END);
	flen=ftell(f);
	if (flen>max_len) return setReason("Variable value from file too long");
	fseek(f,0,SEEK_SET);
	vlen=fread(value,1,flen,f);
	if (vlen!=flen) return setReason("Could not read all of file");
	fclose(f);
	*value_len=vlen;
	return 0;
      }
      break;
    default: /* literal string */
      vlen=strlen((char *)&text[i]);
      if (vlen>max_len) return setReason("Variable value too long");
      bcopy(&text[i],value,vlen);
      *value_len=vlen;
      return 0;
    }

  return 0;
}

