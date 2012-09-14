

/*
 
 Serval Directory Service client
 
 When servald starts, load the SID, IP (or domain name) & port of a directory server.
 When an interface comes up with a route to this server, and periodically thereafter, 
 send our SID name and number to the configured server.
 
 When we perform a lookup, send an additional copy of the request to the directory server.
 
 */

#include "serval.h"
#include "overlay_address.h"

#define MDP_DIRECTORY 999

struct subscriber *directory_service;

// send a registration packet
static void directory_send(struct subscriber *directory_service, const unsigned char *sid, const char *did, const char *name){
  overlay_mdp_frame request;
  
  memset(&request, 0, sizeof(overlay_mdp_frame));
  
  bcopy(sid, request.out.src.sid, SID_SIZE);
  request.out.src.port=MDP_PORT_NOREPLY;
  
  bcopy(request.out.dst.sid, directory_service->sid, SID_SIZE);
  request.out.dst.port=MDP_DIRECTORY;
  request.out.payload_length = snprintf((char *)request.out.payload, sizeof(request.out.payload), 
					"%s|%s", did, name);
  
  overlay_mdp_dispatch(&request, 0, NULL, 0);
}

// send a registration packet for each unlocked identity
static void directory_send_keyring(struct subscriber *directory_service){
  int cn=0, in=0, kp=0, k2;
  
  for (; !keyring_sanitise_position(keyring, &cn, &in, &kp); ++kp){
    keyring_identity *i = keyring->contexts[cn]->identities[in];
    
    if (i->keypairs[kp]->type == KEYTYPE_CRYPTOBOX){
      const unsigned char *packedSid = i->keypairs[0]->public_key;
      
      for(k2=0; k2 < i->keypair_count; k2++){
	if (i->keypairs[k2]->type==KEYTYPE_DID){
	  const char *unpackedDid = (const char *) i->keypairs[kp]->private_key;
	  const char *name = (const char *) i->keypairs[kp]->public_key;
	  
	  directory_send(directory_service, packedSid, unpackedDid, name);
	  // send the first DID only
	  break;
	}
      }
    }
  }
}

static int load_directory_config(){
  const char *sid_hex = confValueGet("directory.service", NULL);
  if (!sid_hex)
    return 0;
  
  unsigned char sid[SID_SIZE];
  if (stowSid(sid, 0, sid_hex)==-1)
    return WHYF("Invalid directory server SID %s", sid_hex);
  
  directory_service = find_subscriber(sid, SID_SIZE, 1);
  if (!directory_service)
    return WHYF("Failed to create subscriber record");
  
  return load_subscriber_address(directory_service);
}

int directory_interface_up(overlay_interface *interface){
  // reload config, now that an interface is up
  load_directory_config();
  
  if (directory_service && subscriber_is_reachable(directory_service) != REACHABLE_NONE){
    directory_send_keyring(directory_service);
  }
  return 0;
}

