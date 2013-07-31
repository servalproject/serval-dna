#include "serval.h"
#include "conf.h"
#include <termios.h>

int overlay_packetradio_setup_port(overlay_interface *interface)
{
  struct termios t;

  if (tcgetattr(interface->alarm.poll.fd, &t))
    WHY_perror("Failed to get terminal parameters");
  speed_t baud_rate;
  switch(interface->uartbps){
  case 0: baud_rate = B0; break;
  case 50: baud_rate = B50; break;
  case 75: baud_rate = B75; break;
  case 110: baud_rate = B110; break;
  case 134: baud_rate = B134; break;
  case 150: baud_rate = B150; break;
  case 200: baud_rate = B200; break;
  case 300: baud_rate = B300; break;
  case 600: baud_rate = B600; break;
  case 1200: baud_rate = B1200; break;
  case 1800: baud_rate = B1800; break;
  case 2400: baud_rate = B2400; break;
  case 4800: baud_rate = B4800; break;
  case 9600: baud_rate = B9600; break;
  case 19200: baud_rate = B19200; break;
  case 38400: baud_rate = B38400; break;
  default:
  case 57600: baud_rate = B57600; break;
  case 115200: baud_rate = B115200; break;
  case 230400: baud_rate = B230400; break;
  }

  if (cfsetospeed(&t, baud_rate))
    WHY_perror("Failed to set output baud rate");
  if (cfsetispeed(&t, baud_rate))
    WHY_perror("Failed to set input baud rate");

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
  
  // Enable/disable CTS/RTS flow control
#ifndef CNEW_RTSCTS
  if (interface->ctsrts) t.c_cflag |= CRTSCTS;
  else t.c_cflag &= ~CRTSCTS;
#else
  if (interface->ctsrts) t.c_cflag |= CNEW_RTSCTS;
  else t.c_cflag &= ~CNEW_RTSCTS;
#endif

  // no output processing
  t.c_oflag &= ~OPOST;

  if (tcsetattr(interface->alarm.poll.fd, TCSANOW, &t))
    WHY_perror("Failed to set terminal parameters");
  
  // Ask radio to report RSSI
  (void)write_all(interface->alarm.poll.fd,"\r",1);
  usleep(600000);
  (void)write_all(interface->alarm.poll.fd,"\r",1);
  usleep(600000);
  (void)write_all(interface->alarm.poll.fd,"+++",3);
  usleep(1200000);
  (void)write_all(interface->alarm.poll.fd,"\rAT&T\rAT&T=RSSI\rATO\r",20);
  if (config.debug.packetradio) {
    tcgetattr(interface->alarm.poll.fd, &t);
    int in_speed=cfgetispeed(&t);
    int out_speed=cfgetospeed(&t);

    DEBUGF("Enabled RSSI reporting for RFD900 radios");
    DEBUGF("Sent ATO to make sure we are in on-line mode");
    DEBUGF("uart speed reported as %d/%d",in_speed,out_speed);
  }
  
  if (0){
    // dummy write of all possible ascii values
    char buff[256];
    int i;
    for (i=0;i<sizeof buff;i++)
      buff[i]=i;
    (void)write_all(interface->alarm.poll.fd,buff,sizeof buff);
  }
  
  set_nonblock(interface->alarm.poll.fd);

  return 0;
}
