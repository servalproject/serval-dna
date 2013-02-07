#include "serval.h"
#include "conf.h"
#include "overlay_address.h"
#include "overlay_buffer.h"
#include "overlay_packet.h"
#include <termios.h>

/* interface decoder states. broadly based on RFC1055 */
#define DC_NORMAL 0
#define DC_ESC 1

/* SLIP-style escape characters used for serial packet radio interfaces */
#define SLIP_END 0xc0
#define SLIP_ESC 0xdb
#define SLIP_ESC_END 0xdc
#define SLIP_ESC_ESC 0xdd

int overlay_packetradio_setup_port(overlay_interface *interface)
{
  struct termios t;

  tcgetattr(interface->alarm.poll.fd, &t);
  // XXX Speed and options should be configurable
  cfsetispeed(&t, B57600);
  cfsetospeed(&t, B57600);
  // 8N1
  t.c_cflag &= ~PARENB;
  t.c_cflag &= ~CSTOPB;
  t.c_cflag &= ~CSIZE;
  t.c_cflag |= CS8;

  // Enable CTS/RTS flow control (for now)
#ifndef CNEW_RTSCTS
  t.c_cflag |= CRTSCTS;
#else
  t.c_cflag |= CNEW_RTSCTS;
#endif
  // and software flow control
  t.c_iflag &= ~(IXON | IXOFF | IXANY);

  // raw data please
  t.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
  t.c_oflag &= ~OPOST;

  tcsetattr(interface->alarm.poll.fd, TCSANOW, &t);

  set_nonblock(interface->alarm.poll.fd);

  return 0;
}

int overlay_rx_packet_complete(overlay_interface *interface)
{
  if (interface->recv_offset) {
    
    struct decode_context context;
    struct overlay_buffer *buffer=ob_static(interface->rxbuffer, interface->recv_offset);
    ob_limitsize(buffer, interface->recv_offset);
    struct overlay_frame frame;
    struct subscriber *next_hop=NULL;
    
    bzero(&context, sizeof(struct decode_context));
    bzero(&frame, sizeof(struct overlay_frame));
    
    if (parseEnvelopeHeader(&context, interface, NULL, buffer))
      goto end;
    
    int packetFlags = parseMdpPacketHeader(&context, &frame, buffer, &next_hop);
    if (packetFlags<=0)
      goto end;
    
    frame.payload = ob_slice(buffer, ob_position(buffer), ob_remaining(buffer));
    ob_limitsize(frame.payload, ob_remaining(buffer));
    
    // forward payloads that are for someone else or everyone
    if (packetFlags&HEADER_FORWARD)
      overlay_forward_payload(&frame);
    
    // process payloads that are for me or everyone
    if (packetFlags&HEADER_PROCESS)
      process_incoming_frame(gettime_ms(), interface, &frame, &context);

    ob_free(frame.payload);
    
  end:
    send_please_explain(&context, my_subscriber, context.sender);
    
    ob_free(buffer);
  }
  interface->recv_offset=0;
  return 0;
}

int overlay_rx_packet_append_byte(overlay_interface *interface,unsigned char byte)
{
  // Make sure we don't put the data outside the RX buffer
  if (interface->recv_offset<0
      ||interface->recv_offset>=OVERLAY_INTERFACE_RX_BUFFER_SIZE)
    interface->recv_offset=0;
  
  interface->rxbuffer[interface->recv_offset++]=byte;
  if (interface->recv_offset==OVERLAY_INTERFACE_RX_BUFFER_SIZE) {
    // packet fills buffer.  Who knows, we might be able to decode what we
    // have of it.
    return overlay_rx_packet_complete(interface);
  } 

  return 0;
}

static void write_buffer(overlay_interface *interface){
  if (interface->tx_bytes_pending>0) {
    int written=write(interface->alarm.poll.fd,interface->txbuffer,
		      interface->tx_bytes_pending);
    if (config.debug.packetradio) DEBUGF("Trying to write %d bytes",
					 interface->tx_bytes_pending);
    if (written>0) {
      interface->tx_bytes_pending-=written;
      bcopy(&interface->txbuffer[written],&interface->txbuffer[0],
	    interface->tx_bytes_pending);
      if (config.debug.packetradio) DEBUGF("Wrote %d bytes (%d left pending)",
					   written,interface->tx_bytes_pending);
    } else {
      if (config.debug.packetradio) DEBUGF("Failed to write any data");
    }
  }
  
  if (interface->tx_bytes_pending>0) {
    // more to write, so keep POLLOUT flag
    interface->alarm.poll.events|=POLLOUT;
  } else {
    // nothing more to write, so clear POLLOUT flag
    interface->alarm.poll.events&=~POLLOUT;
    // try to empty another packet from the queue ASAP
    overlay_queue_schedule_next(gettime_ms());
  }
  watch(&interface->alarm);
}

void overlay_packetradio_poll(struct sched_ent *alarm)
{
  overlay_interface *interface = (overlay_interface *)alarm;

  time_ms_t now = gettime_ms();
  
  if (alarm->poll.revents==0){
    if (interface->state==INTERFACE_STATE_UP && 
	(interface->last_tick_ms==-1 || interface->last_tick_ms + interface->tick_ms<now)){
      // tick the interface
      overlay_route_queue_advertisements(interface);
      interface->last_tick_ms=now;
    }
    alarm->alarm=interface->last_tick_ms + interface->tick_ms;
    alarm->deadline=alarm->alarm + interface->tick_ms/2;
    unschedule(alarm);
    schedule(alarm);
    return;
  }
  
  if (alarm->poll.revents&POLLOUT){
    write_buffer(interface);
  }

  // Read data from the serial port
  if (alarm->poll.revents&POLLIN){
    unsigned char buffer[OVERLAY_INTERFACE_RX_BUFFER_SIZE];
    ssize_t nread = read(alarm->poll.fd, buffer, OVERLAY_INTERFACE_RX_BUFFER_SIZE);
    if (nread == -1){
      // WHY_perror("read");
      return;
    }
    if (nread>0) {
      /*
	Examine received bytes for end of packet marker.
	The challenge is that we need to make sure that the packet encapsulation
	is self-synchronising in the event that a data error occurs (including
	failure to receive an arbitrary number of bytes).
	For now we will reuse the functional but sub-optimal method described in
	RFC1055 for SLIP.
      */
      int i;
      for(i=0;i<nread;i++)
	{
	  switch (interface->decoder_state) {
	  case DC_ESC:
	    // escaped character
	    interface->decoder_state=DC_NORMAL;
	    switch(buffer[i]) {
	    case SLIP_ESC_END: // escaped END byte
	      overlay_rx_packet_append_byte(interface,SLIP_END);
	    break;
	  case SLIP_ESC_ESC: // escaped escape character
	    overlay_rx_packet_append_byte(interface,SLIP_ESC); 
	    break;
	  default: /* Unknown escape character. This is an error. */
	    if (config.debug.packetradio)
		WARNF("Packet radio stream contained illegal escaped byte 0x%02x -- ignoring packet.",buffer[i]);
	      // interface->recv_offset=0;
	    break;
	  }
	  break;
	default:
	  // non-escape character
	  switch(buffer[i]) {
	  case SLIP_ESC:
	    interface->decoder_state=DC_ESC; 
	    break;
	  case SLIP_END:
	    overlay_rx_packet_complete(interface);
	    break;
	  default:
	    overlay_rx_packet_append_byte(interface,buffer[i]);
	  }
	  break;
	}
      }
    }
  }
  
  return ;
}

static int encode(unsigned char *src, int src_bytes, unsigned char *dst, int dst_len){
  int offset=0;
  int i;
  for (i=0;i<src_bytes;i++){
    
    if (offset+2>dst_len)
      return WHY("Buffer overflow while encoding frame");
    
    switch(src[i]) {
      case SLIP_END:
	dst[offset++]=SLIP_ESC;
	dst[offset++]=SLIP_ESC_END;
	break;
      case SLIP_ESC:
	dst[offset++]=SLIP_ESC;
	dst[offset++]=SLIP_ESC_ESC;
	break;
      default:
	dst[offset++]=src[i];
    }
  }
  return offset;
}

int overlay_packetradio_tx_packet(struct overlay_frame *frame)
{
  /*
    This is a bit interesting, because we have to deal with RTS/CTS potentially
    blocking our writing of the packet.

    For now, just try to write it, and if we only write part of it, then so be it.

    We will surround each packet with SLIP END characters, so we should be able to
    deal with such truncation in a fairly sane manner.
  */
  overlay_interface *interface=frame->interface;
  int interface_number = interface - overlay_interfaces;
  
  if (frame->payload->position>OVERLAY_INTERFACE_RX_BUFFER_SIZE)
    return WHYF("Not sending over-size packet");
  if (interface->tx_bytes_pending>0)
    return WHYF("Cannot send two packets at the same time");

  struct overlay_buffer *headers=ob_new();
  if (!headers) 
    return WHY("could not allocate overlay buffer for headers");
  
  
  struct decode_context context;
  bzero(&context, sizeof(struct decode_context));
  
  if (frame->source_full)
    my_subscriber->send_full=1;
  
  if (overlay_packet_init_header(&context, headers, NULL, 0, interface_number, 0))
    goto cleanup;
  
  struct broadcast *broadcast=NULL;
  if ((!frame->destination) && !is_all_matching(frame->broadcast_id.id,BROADCAST_LEN,0))
    broadcast = &frame->broadcast_id;
  
  if (overlay_frame_build_header(&context, headers,
				 frame->queue, frame->type, 
				 frame->modifiers, frame->ttl,
				 broadcast, frame->next_hop, 
				 frame->destination, frame->source))
    goto cleanup;
    
  /* Encode packet with SLIP escaping.
     XXX - Add error correction here also */
  unsigned char *buffer = interface->txbuffer;
  int out_len=0;

  buffer[out_len++]=SLIP_END;
  
  int encoded=encode(headers->bytes, headers->position, 
		     buffer+out_len, sizeof(interface->txbuffer) - out_len);
  if (encoded<0){
    WHY("Ran out of buffer space while encoding headers");
    goto cleanup;
  }
  
  out_len+=encoded;
  
  encoded=encode(frame->payload->bytes, frame->payload->position, 
		  buffer+out_len, sizeof(interface->txbuffer) - out_len);
  if (encoded<0){
    WHY("Ran out of buffer space while encoding payload body");
    goto cleanup;
  }
  
  out_len+=encoded;
  buffer[out_len++]=SLIP_END;

  if (config.debug.packetradio){
    DEBUGF("Encoded length is %d",out_len);
  }
  
  interface->tx_bytes_pending=out_len;
  write_buffer(interface);
  
  ob_free(headers);
  return 0;
  
cleanup:
  ob_free(headers);
  return -1;
}

