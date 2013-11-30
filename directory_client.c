

/*
 
 Serval Directory Service client
 
 When servald starts, load the SID, IP (or domain name) & port of a directory server.
 When an interface comes up with a route to this server, and periodically thereafter, 
 send our SID name and number to the configured server.
 
 When we perform a lookup, send an additional copy of the request to the directory server.
 
 */

#include "serval.h"
#include "str.h"
#include "overlay_address.h"
#include "conf.h"
#include "keyring.h"

struct subscriber *directory_service;

static void directory_update(struct sched_ent *alarm);

static struct profile_total directory_timing={
  .name="directory_update",
};

struct sched_ent directory_alarm={
  .function=directory_update,
  .stats=&directory_timing,
};
#define DIRECTORY_UPDATE_INTERVAL 120000

// send a registration packet
static void directory_send(struct subscriber *directory_service, const sid_t *sidp, const char *did, const char *name)
{
  overlay_mdp_frame request;
  
  memset(&request, 0, sizeof(overlay_mdp_frame));
  
  request.packetTypeAndFlags = MDP_TX;
  
  request.out.src.sid = *sidp;
  request.out.src.port=MDP_PORT_NOREPLY;
  request.out.queue=OQ_ORDINARY;
  
  request.out.dst.sid = directory_service->sid;
  request.out.dst.port=MDP_PORT_DIRECTORY;
  request.out.payload_length = snprintf((char *)request.out.payload, sizeof(request.out.payload), 
					"%s|%s", did, name);
  // Used by tests
  INFOF("Sending directory registration for %s*, %s, %s to %s*", 
	alloca_tohex_sid_t_trunc(*sidp, 14), did, name, alloca_tohex_sid_t_trunc(directory_service->sid, 14));
  overlay_mdp_dispatch(&request, NULL);
}

// send a registration packet for each unlocked identity
static void directory_send_keyring(struct subscriber *directory_service){
  int cn=0, in=0, kp=0, k2;
  
  for (; !keyring_sanitise_position(keyring, &cn, &in, &kp); ++kp){
    keyring_identity *i = keyring->contexts[cn]->identities[in];
    
    if (i->keypairs[kp]->type == KEYTYPE_CRYPTOBOX){
      const sid_t *sidp = (const sid_t *) i->keypairs[0]->public_key;
      
      for(k2=0; k2 < i->keypair_count; k2++){
	if (i->keypairs[k2]->type==KEYTYPE_DID){
	  const char *unpackedDid = (const char *) i->keypairs[k2]->private_key;
	  const char *name = (const char *) i->keypairs[k2]->public_key;
	  
	  directory_send(directory_service, sidp, unpackedDid, name);
	  // send the first DID only
	  break;
	}
      }
    }
  }
}

static int load_directory_config()
{
  if (!directory_service && !is_sid_t_any(config.directory.service)) {
    directory_service = find_subscriber(config.directory.service.binary, SID_SIZE, 1);
    if (!directory_service)
      return WHYF("Failed to create subscriber record");
    // used by tests
    INFOF("ADD DIRECTORY SERVICE %s", alloca_tohex_sid_t(directory_service->sid));
  }
  // always attempt to reload the address, may depend on DNS resolution
  return load_subscriber_address(directory_service);
}

static void directory_update(struct sched_ent *alarm){
  load_directory_config();
  
  if (directory_service){
    if (directory_service->reachable & REACHABLE){
      directory_send_keyring(directory_service);
      
      unschedule(alarm);
      alarm->alarm = gettime_ms() + DIRECTORY_UPDATE_INTERVAL;
      alarm->deadline = alarm->alarm + 10000;
      schedule(alarm);
    }else
      DEBUGF("Directory service is not reachable");
  }
}

int directory_service_init(){
  directory_update(&directory_alarm);
  return 0;
}

// called when we discover a route to the directory service SID
int directory_registration(){
  // give the route & SAS keys a moment to propagate
  unschedule(&directory_alarm);
  directory_alarm.alarm = gettime_ms() + 200;
  directory_alarm.deadline = directory_alarm.alarm + 10000;
  schedule(&directory_alarm);
  return 0;
}

