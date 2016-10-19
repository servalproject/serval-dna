/*
Serval DNA keyring MDP key map request
Copyright (C) 2016 Flinders University
Copyright (C) 2010-2015 Serval Project Inc.
Copyright (C) 2010-2012 Paul Gardner-Stephen
 
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

#include "keyring.h"
#include "conf.h"
#include "debug.h"
#include "overlay_buffer.h"
#include "crypto.h"
#include "mem.h"

static int keyring_respond_id(struct internal_mdp_header *header)
{
  keyring_identity *id = header->destination->identity;

  /* It's a request, so find the SAS for the SID the request was addressed to,
     use that to sign that SID, and then return it in an authcrypted frame. */
  struct internal_mdp_header response;
  bzero(&response, sizeof response);
  mdp_init_response(header, &response);
  
  uint8_t buff[MDP_MTU];
  struct overlay_buffer *response_payload = ob_static(buff, sizeof buff);
  ob_limitsize(response_payload, sizeof buff);
  
  ob_append_byte(response_payload, KEYTYPE_CRYPTOSIGN);
  ob_append_bytes(response_payload, id->sign_keypair->public_key.binary, crypto_sign_PUBLICKEYBYTES);
  uint8_t *sig = ob_append_space(response_payload, crypto_sign_BYTES);

  if (crypto_sign_detached(sig, NULL, header->destination->sid.binary, SID_SIZE, id->sign_keypair->binary))
    return WHY("crypto_sign() failed");
    
  DEBUGF(keyring, "Sending SID:SAS mapping, %zd bytes, %s:%"PRImdp_port_t" -> %s:%"PRImdp_port_t,
	 ob_position(response_payload),
	 alloca_tohex_sid_t(header->destination->sid), header->destination_port,
	 alloca_tohex_sid_t(header->source->sid), header->source_port
        );
  
  ob_flip(response_payload);
  int ret = overlay_send_frame(&response, response_payload);
  ob_free(response_payload);
  return ret;
}

static int keyring_store_id(struct internal_mdp_header *header, struct overlay_buffer *payload)
{
  if (header->source->id_valid){
    DEBUGF(keyring, "Ignoring SID:SAS mapping for %s, already have one", alloca_tohex_sid_t(header->source->sid));
    return 0;
  }
  size_t len = ob_remaining(payload);
  
  DEBUGF(keyring, "Received SID:SAS mapping, %zd bytes", len);
  
  if (ob_remaining(payload) < IDENTITY_SIZE + crypto_sign_BYTES)
    return WHY("Truncated key mapping announcement?");
  
  const uint8_t *id_public = ob_get_bytes_ptr(payload, IDENTITY_SIZE);
  const uint8_t *compactsignature = ob_get_bytes_ptr(payload, crypto_sign_BYTES);

  if (crypto_sign_verify_detached(compactsignature, header->source->sid.binary, SID_SIZE, id_public))
    return WHY("SID:SAS mapping verification signature does not verify");

  // test if the signing key can be used to derive the sid
  sid_t sid;
  if (crypto_sign_ed25519_pk_to_curve25519(sid.binary, id_public)==0
    && memcmp(&sid, &header->source->sid, sizeof sid) == 0)
    header->source->id_combined=1;

  /* now store it */
  bcopy(id_public, &header->source->id_public, IDENTITY_SIZE);
  header->source->id_valid=1;
  header->source->id_last_request=-1;
  
  DEBUGF(keyring, "Stored SID:SAS mapping, SID=%s to SAS=%s",
	 alloca_tohex_sid_t(header->source->sid),
	 alloca_tohex_identity_t(&header->source->id_public)
	);
  return 0;
}

static int keyring_send_challenge(struct subscriber *source, struct subscriber *dest)
{
  struct internal_mdp_header header;
  bzero(&header, sizeof header);
  
  header.source = source;
  header.destination = dest;
  header.source_port = MDP_PORT_KEYMAPREQUEST;
  header.destination_port = MDP_PORT_KEYMAPREQUEST;
  header.qos = OQ_MESH_MANAGEMENT;
  
  time_ms_t now = gettime_ms();

  struct keyring_challenge *challenge = source->identity->challenge;
  if (challenge && challenge->expires < now){
    free(challenge);
    challenge = NULL;
  }
  if (!challenge){
    challenge = emalloc_zero(sizeof(struct keyring_challenge));
    if (challenge){
      // give the remote party 15s to respond (should this could be based on measured link latency?)
      challenge->expires = now + 15000;
      randombytes_buf(challenge->challenge, sizeof(challenge->challenge));
    }
  }
  source->identity->challenge = challenge;
  if (!challenge)
    return -1;

  struct overlay_buffer *payload = ob_new();
  ob_append_byte(payload, UNLOCK_CHALLENGE);
  ob_append_bytes(payload, challenge->challenge, sizeof challenge->challenge);
  
  DEBUGF(keyring, "Sending Unlock challenge for sid %s", alloca_tohex_sid_t(source->sid));
    
  ob_flip(payload);
  int ret = overlay_send_frame(&header, payload);
  ob_free(payload);
  return ret;
}

static int keyring_respond_challenge(struct subscriber *subscriber, struct overlay_buffer *payload)
{
  if (!subscriber->identity)
    return WHY("Cannot unlock an identity we don't have in our keyring");
  if (subscriber->reachable==REACHABLE_SELF)
    return 0;
    
  struct internal_mdp_header header;
  bzero(&header, sizeof header);

  header.source = get_my_subscriber(1);
  header.destination = subscriber;
  header.source_port = MDP_PORT_KEYMAPREQUEST;
  header.destination_port = MDP_PORT_KEYMAPREQUEST;
  header.qos = OQ_MESH_MANAGEMENT;
  
  uint8_t buff[MDP_MTU];
  struct overlay_buffer *response = ob_static(buff, sizeof buff);
  ob_append_byte(response, UNLOCK_RESPONSE);
  ob_append_bytes(response, ob_current_ptr(payload), ob_remaining(payload));
  
  size_t len = ob_position(response);
  if (keyring_sign_message(subscriber->identity, ob_ptr(response), sizeof(buff), &len))
    return -1;
    
  ob_append_space(response, len - ob_position(response));
  DEBUGF(keyring, "Responding to Unlock challenge for sid %s", alloca_tohex_sid_t(subscriber->sid));
  ob_flip(response);
  int ret = overlay_send_frame(&header, response);
  ob_free(response);
  return ret;
}

static int keyring_process_challenge(keyring_file *k, struct subscriber *subscriber, struct overlay_buffer *payload)
{
  int ret=-1;
  time_ms_t now = gettime_ms();

  struct keyring_challenge *challenge = subscriber->identity->challenge;

  if (challenge){
    subscriber->identity->challenge = NULL;
    size_t len = ob_remaining(payload)+1;
    // verify that the payload was signed by our key and contains the same challenge bytes that we sent
    // TODO allow for signing the challenge bytes without sending them twice?
    if (challenge->expires >= now
      && crypto_verify_message(subscriber, ob_current_ptr(payload) -1, &len) == 0
      && len - 1 == sizeof(challenge->challenge)
      && memcmp(ob_current_ptr(payload), challenge->challenge, sizeof(challenge->challenge)) == 0){

      keyring_release_subscriber(k, &subscriber->sid);
      ret=0;
    }else{
      WHY("Challenge failed");
    }
    free(challenge);
  }
  return ret;
}

DEFINE_BINDING(MDP_PORT_KEYMAPREQUEST, keyring_mapping_request);
static int keyring_mapping_request(struct internal_mdp_header *header, struct overlay_buffer *payload)
{

  /* The authcryption of the MDP frame proves that the SAS key is owned by the
     owner of the SID, and so is absolutely compulsory. */
  if (header->crypt_flags&(MDP_NOCRYPT|MDP_NOSIGN)) 
    return WHY("mapping requests must be performed under authcryption");
    
  switch(ob_get(payload)){
    case KEYTYPE_CRYPTOSIGN:
      if (ob_remaining(payload)==0)
	return keyring_respond_id(header);
      return keyring_store_id(header, payload);
      break;
    case UNLOCK_REQUEST:
      {
	size_t len = ob_remaining(payload) +1;
	if (crypto_verify_message(header->destination, ob_current_ptr(payload) -1, &len))
	  return WHY("Signature check failed");
      }
      return keyring_send_challenge(header->destination, header->source);
    case UNLOCK_CHALLENGE:
      return keyring_respond_challenge(header->source, payload);
    case UNLOCK_RESPONSE:
      return keyring_process_challenge(keyring, header->destination, payload);
  }
  return WHY("Not implemented");
}
