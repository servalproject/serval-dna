#include "serval.h"
#include "conf.h"
#include <termios.h>

/* interface decoder states. broadly based on RFC1055 */
#define DC_NORMAL 0
#define DC_ESC 1
#define DC_END 2

/* SLIP-style escape characters used for serial packet radio interfaces */
#define SLIP_END 0300
#define SLIP_ESC 0333
#define SLIP_ESC_END 0334
#define SLIP_ESC_ESC 0335

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

  // Disable CTS/RTS flow control (for now)
#ifndef CNEW_RTSCTS
  t.c_cflag &= ~CRTSCTS;
#else
  t.c_cflag &= ~CNEW_RTSCTS;
#endif
  // and software flow control
  t.c_iflag &= ~(IXON | IXOFF | IXANY);

  // raw data please
  t.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
  t.c_oflag &= ~OPOST;

  tcsetattr(interface->alarm.poll.fd, TCSANOW, &t);
  return 0;
}

int overlay_rx_packet_complete(overlay_interface *interface)
{
  if (interface->recv_offset) {
    // dispatch received packet
    if (packetOkOverlay(interface, interface->buffer, interface->recv_offset, -1, 
			NULL,0)) {
      if (config.debug.packetradio)
	WARN("Corrupted or unsupported packet from packet radio interface");
    }
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
  
  interface->buffer[interface->recv_offset++]=byte;
  if (interface->recv_offset==OVERLAY_INTERFACE_RX_BUFFER_SIZE) {
    // packet fills buffer.  Who knows, we might be able to decode what we
    // have of it.
    return overlay_rx_packet_complete(interface);
  } 

  if (config.debug.packetradio) DEBUGF("RXd %d bytes",interface->recv_offset);
  return 0;
}

void overlay_packetradio_poll(struct sched_ent *alarm)
{
  overlay_interface *interface = (overlay_interface *)alarm;
  time_ms_t now = gettime_ms();

  // Read data from the serial port
  // We will almost certainly support more than one type of packet radio
  // so lets parameterise this.
  switch(1) {
  case 1:
    {
      unsigned char buffer[OVERLAY_INTERFACE_RX_BUFFER_SIZE];
      ssize_t nread = read(alarm->poll.fd, buffer, OVERLAY_INTERFACE_RX_BUFFER_SIZE);
      if (nread == -1){
	WHY_perror("read");
	return;
      }
      if (nread>0) {
	/*
	  Examine received bytes for end of packet marker.
	  The challenge is that we need to make sure that the packet encapsulation
	  is self-synchronising in the event that a data error occurs (including
	  failure to receive an arbitrary number of bytes).
	  For now we will reuse the antiquated and sub-optimal method described in
	  RFC1055 for SLIP, but with a couple of tweaks to reduce byte wastage when
	  encountering ESC and END characters in packets.
	*/
	int i;
	for(i=0;i<nread;i++)
	  {
	    switch (interface->decoder_state) {
	    case DC_ESC:
	      // escaped character
	      switch(buffer[i]) {
	      case SLIP_ESC_END: // escaped END byte
		overlay_rx_packet_append_byte(interface,SLIP_END); break;
	      case SLIP_ESC_ESC: // escaped escape character
		overlay_rx_packet_append_byte(interface,SLIP_ESC); break;
	      default: /* unknown escape character
			  This is where the inefficiency comes, because
			  we don't use the spare bits.
			  We can reduce the inefficiency by making ESC <otherbyte>
			  mean literally that. */
		overlay_rx_packet_append_byte(interface,SLIP_ESC); 
		overlay_rx_packet_append_byte(interface,buffer[i]);
		break;
	      }
	      break;
	    case DC_END:
	      // character preceeded by END character
	      switch(buffer[i]) {
	      case SLIP_ESC_END:
		overlay_rx_packet_complete(interface);
		break;
	      default:
		overlay_rx_packet_append_byte(interface,SLIP_END); 
		overlay_rx_packet_append_byte(interface,buffer[i]);
		break;
	      }
	      break;
	    default:
	      // non-escape character
	      switch(buffer[i]) {
	      case SLIP_ESC:
		interface->decoder_state=DC_ESC; break;
	      case SLIP_END:
		interface->decoder_state=DC_END; break;
	      default:
		overlay_rx_packet_append_byte(interface,buffer[i]);
	      }
	      break;
	    }
	  }
      }
    }
    break;
  }

  // tick the interface
  if (interface->tick_ms>0 && 
      (interface->last_tick_ms == -1 || now >= interface->last_tick_ms + interface->tick_ms)) {
    // tick the interface
    overlay_route_queue_advertisements(interface);
    interface->last_tick_ms=now;
  }
  
  schedule(alarm);

  return ;
}

