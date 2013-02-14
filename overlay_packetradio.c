#include "serval.h"
#include "conf.h"
#include <termios.h>

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

  t.c_lflag &= ~(ICANON | ISIG | IEXTEN | ECHO | ECHOE);
  /* Noncanonical mode, disable signals, extended
   input processing, and software flow control and echoing */
  
  t.c_iflag &= ~(BRKINT | ICRNL | IGNBRK | IGNCR | INLCR |
		 INPCK | ISTRIP | IXON | IXOFF | IXANY | PARMRK);
  /* Disable special handling of CR, NL, and BREAK.
   No 8th-bit stripping or parity error handling.
   Disable START/STOP output flow control. */
  
  // Enable CTS/RTS flow control (for now)
#ifndef CNEW_RTSCTS
  t.c_cflag |= CRTSCTS;
#else
  t.c_cflag |= CNEW_RTSCTS;
#endif

  // no output processing
  t.c_oflag &= ~OPOST;

  tcsetattr(interface->alarm.poll.fd, TCSANOW, &t);

  write(interface->alarm.poll.fd,"ATO\r",4);
  if (config.debug.packetradio)
    DEBUGF("Sent ATO to make sure we are in on-line mode");
  
  if (0){
    // dummy write of all possible ascii values
    char buff[256];
    int i;
    for (i=0;i<sizeof buff;i++)
      buff[i]=i;
    write(interface->alarm.poll.fd,buff,sizeof buff);
  }
  
  set_nonblock(interface->alarm.poll.fd);

  return 0;
}
