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

  write(interface->alarm.poll.fd,"ATO\r",4);
  if (config.debug.packetradio)
    DEBUGF("Sent ATO to make sure we are in on-line mode");
  
  set_nonblock(interface->alarm.poll.fd);

  return 0;
}
