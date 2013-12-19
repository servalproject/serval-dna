
#include "serval.h"
#include "str.h"
#include "strbuf.h"
#include "strbuf_helpers.h"
#include "dataformats.h"
#include "mdp_client.h"
#include "msp_client.h"
#include "socket.h"

struct buffer{
  size_t position;
  size_t limit;
  size_t capacity;
  uint8_t bytes[];
};

struct connection{
  struct sched_ent alarm_in;
  struct sched_ent alarm_out;
  struct msp_sock *sock;
  struct buffer *in;
  struct buffer *out;
  int last_state;
};

int saw_error=0;
int once =0;
struct msp_sock *listener=NULL;
struct mdp_sockaddr remote_addr;
struct socket_address ip_addr;

static int try_send(struct connection *conn);
static void msp_poll(struct sched_ent *alarm);
static void listen_poll(struct sched_ent *alarm);
static void io_poll(struct sched_ent *alarm);

struct profile_total mdp_sock_stats={
  .name="msp_poll"
};

struct sched_ent mdp_sock={
  .poll.revents = 0,
  .poll.events = POLLIN,
  .poll.fd = -1,
  .function = msp_poll,
  .stats = &mdp_sock_stats,
};

struct profile_total io_stats={
  .name="io_stats"
};

struct profile_total listen_stats={
  .name="listen_poll"
};

struct sched_ent listen_alarm={
  .poll.revents = 0,
  .poll.events = POLLIN,
  .poll.fd = -1,
  .function = listen_poll,
  .stats = &listen_stats,
};

static struct connection *alloc_connection(
  struct msp_sock *sock,
  int fd_in,
  void (*func_in)(struct sched_ent *alarm),
  int fd_out,
  void (*func_out)(struct sched_ent *alarm))
{
  struct connection *conn = emalloc_zero(sizeof(struct connection));
  if (!conn)
    return NULL;
  
  conn->sock = sock;
  conn->alarm_in.poll.fd = fd_in;
  conn->alarm_in.poll.events = POLLIN;
  conn->alarm_in.function = func_in;
  conn->alarm_in.stats = &io_stats;
  conn->alarm_in.context = conn;
  conn->alarm_out.poll.fd = fd_out;
  conn->alarm_out.poll.events = POLLOUT;
  conn->alarm_out.function = func_out;
  conn->alarm_out.stats = &io_stats;
  conn->alarm_out.context = conn;
  watch(&conn->alarm_in);
  conn->in = emalloc(1024 + sizeof(struct buffer));
  if (!conn->in){
    free(conn);
    return NULL;
  }
  conn->out = emalloc(1024 + sizeof(struct buffer));
  if (!conn->out){
    free(conn->in);
    free(conn);
    return NULL;
  }
  conn->in->position = conn->out->position = 0;
  conn->in->limit = conn->out->limit = 0;
  conn->in->capacity = conn->out->capacity = 1024;
  return conn;
}

static void free_connection(struct connection *conn)
{
  if (!conn)
    return;
  if (is_watching(&conn->alarm_in))
    unwatch(&conn->alarm_in);
  if (is_watching(&conn->alarm_out))
    unwatch(&conn->alarm_out);
  if (conn->in)
    free(conn->in);
  if (conn->out)
    free(conn->out);
  if (conn->alarm_in.poll.fd!=-1)
    close(conn->alarm_in.poll.fd);
  if (conn->alarm_out.poll.fd!=-1 && conn->alarm_out.poll.fd != conn->alarm_in.poll.fd)
    close(conn->alarm_out.poll.fd);
  conn->in=NULL;
  conn->out=NULL;
  conn->alarm_in.poll.fd=-1;
  conn->alarm_out.poll.fd=-1;
  free(conn);

  if (msp_socket_count()==0){
    unschedule(&mdp_sock);
    
    if (is_watching(&mdp_sock))
      unwatch(&mdp_sock);
  }
}

static void process_msp_asap()
{
  mdp_sock.alarm = gettime_ms();
  mdp_sock.deadline = mdp_sock.alarm+10;
  unschedule(&mdp_sock);
  schedule(&mdp_sock);
}

static int msp_handler(struct msp_sock *sock, msp_state_t state, const uint8_t *payload, size_t len, void *context)
{
  struct connection *conn = context;
  conn->last_state=state;
  
  if (state & MSP_STATE_ERROR)
    saw_error=1;
    
  if (payload && len){
    if (conn->out->limit){
      // attempt to write immediately
      conn->alarm_out.poll.revents=POLLOUT;
      conn->alarm_out.function(&conn->alarm_out);
    }
    if (conn->out->capacity < len + conn->out->limit)
      return 1;
    
    bcopy(payload, &conn->out->bytes[conn->out->limit], len);
    conn->out->limit+=len;
    if (!is_watching(&conn->alarm_out))
      watch(&conn->alarm_out);
    
    // attempt to write immediately
    conn->alarm_out.poll.revents=POLLOUT;
    conn->alarm_out.function(&conn->alarm_out);
  }
  
  if (state & MSP_STATE_CLOSED){
    struct mdp_sockaddr remote;
    msp_get_remote_adr(sock, &remote);
    INFOF(" - Connection with %s:%d closed", alloca_tohex_sid_t(remote.sid), remote.port);
    
    conn->sock = NULL;
    if (is_watching(&conn->alarm_in))
      unwatch(&conn->alarm_in);
    if (!is_watching(&conn->alarm_out))
      free_connection(conn);
    
    return 0;
  }
  
  if (state&MSP_STATE_DATAOUT)
    try_send(conn);
  return 0;
}

static int msp_listener(struct msp_sock *sock, msp_state_t state, const uint8_t *payload, size_t len, void *UNUSED(context))
{
  if (state & MSP_STATE_ERROR){
    WHY("Error listening for incoming connections");
  }
  if (state & MSP_STATE_CLOSED){
    if (msp_socket_count()==0){
      unschedule(&mdp_sock);
      
      if (is_watching(&mdp_sock))
	unwatch(&mdp_sock);
    }
    return 0;
  }
  
  struct mdp_sockaddr remote;
  msp_get_remote_adr(sock, &remote);
  INFOF(" - New connection from %s:%d", alloca_tohex_sid_t(remote.sid), remote.port);
  int fd_in = STDIN_FILENO;
  int fd_out = STDOUT_FILENO;
  
  if (ip_addr.addrlen){
    int fd = esocket(PF_INET, SOCK_STREAM, 0);
    if (fd==-1){
      msp_close(sock);
      return -1;
    }
    if (socket_connect(fd, &ip_addr.addr, ip_addr.addrlen)==-1){
      msp_close(sock);
      close(fd);
      return -1;
    }
    fd_in = fd_out = fd;
  }
  struct connection *conn = alloc_connection(sock, fd_in, io_poll, fd_out, io_poll);
  if (!conn)
    return -1;
    
  conn->sock = sock;
  watch(&conn->alarm_in);
  msp_set_handler(sock, msp_handler, conn);
  if (payload)
    return msp_handler(sock, state, payload, len, conn);
  
  if (once){
    // stop listening after the first incoming connection
    msp_close(listener);
  }
  return 0;
}

static void msp_poll(struct sched_ent *alarm)
{
  if (alarm->poll.revents & POLLIN)
    // process incoming data packet
    msp_recv(alarm->poll.fd);
  
  // do any timed actions that need to be done, either in response to receiving or due to a timed alarm.
  msp_processing(&alarm->alarm);
  if (alarm->alarm){
    time_ms_t now = gettime_ms();
    if (alarm->alarm < now)
      alarm->alarm = now;
    alarm->deadline = alarm->alarm +10;
    unschedule(alarm);
    schedule(alarm);
  }
}

static void local_shutdown(struct connection *conn)
{
  struct mdp_sockaddr remote;
  msp_get_remote_adr(conn->sock, &remote);
  msp_shutdown(conn->sock);
  INFOF(" - Connection with %s:%d local shutdown", alloca_tohex_sid_t(remote.sid), remote.port);
}

static int try_send(struct connection *conn)
{
  if (!conn->in->limit)
    return 0;
  if (msp_send(conn->sock, conn->in->bytes, conn->in->limit)==-1)
    return 0;
  
  // if this packet was acceptted, clear the read buffer
  conn->in->limit = conn->in->position = 0;
  // hit end of data?
  if (conn->alarm_in.poll.events==0){
    local_shutdown(conn);
  }else{
    if (!is_watching(&conn->alarm_in))
      watch(&conn->alarm_in);
  }
  return 1;
}

static void io_poll(struct sched_ent *alarm)
{
  struct connection *conn = alarm->context;
  
  if (alarm->poll.revents & POLLIN) {
    size_t remaining = conn->in->capacity - conn->in->limit;
    if (remaining>0){
      ssize_t r = read(alarm->poll.fd, 
	conn->in->bytes + conn->in->limit,
	remaining);
      if (r>0){
	conn->in->limit+=r;
	if (try_send(conn))
	  process_msp_asap();
	// stop reading input when the buffer is full
	if (conn->in->limit==conn->in->capacity){
	  unwatch(alarm);
	}
      }else{
	// EOF? trigger a graceful shutdown
	alarm->poll.revents = POLLHUP;
      }
    }
  }
  
  if (alarm->poll.revents & POLLOUT) {
    // try to write some data
    size_t data = conn->out->limit-conn->out->position;
    if (data>0){
      ssize_t r = write(alarm->poll.fd, 
	conn->out->bytes+conn->out->position,
	data);
      if (r > 0)
	conn->out->position+=r;
    }
    
    // if the buffer is empty now, reset it and unwatch the handle
    if (conn->out->position==conn->out->limit){
      conn->out->limit = conn->out->position = 0;
      if (is_watching(alarm))
	unwatch(alarm);
    }
    
    if (conn->out->limit < conn->out->capacity){
      if (conn->sock){
	process_msp_asap();
      }else{
	free_connection(conn);
      }
    }
  }
  
  if (alarm->poll.revents & POLLHUP) {
    // EOF? trigger a graceful shutdown
    unwatch(alarm);
    alarm->poll.events = 0;
    if (!conn->in->limit){
      local_shutdown(conn);
      process_msp_asap();
    }
  }
  
  if (alarm->poll.revents & POLLERR) {
    free_connection(conn);
    process_msp_asap();
  }
}

static void listen_poll(struct sched_ent *alarm)
{
  if (alarm->poll.revents & POLLIN) {
    struct socket_address addr;
    addr.addrlen = sizeof addr.store;
    int fd = accept(alarm->poll.fd, &addr.addr, &addr.addrlen);
    if (fd==-1){
      WHYF_perror("accept(%d)", alarm->poll.fd);
      return;
    }
    INFOF("- Incoming TCP connection from %s", alloca_socket_address(&addr));
    struct msp_sock *sock = msp_socket(mdp_sock.poll.fd);
    if (!sock)
      return;
    
    struct connection *connection = alloc_connection(sock, fd, io_poll, fd, io_poll);
    if (!connection){
      msp_close(sock);
      return;
    }

    msp_set_handler(sock, msp_handler, connection);
    msp_set_remote(sock, remote_addr);
    
    if (once){
      unwatch(alarm);
      close(alarm->poll.fd);
      alarm->poll.fd=-1;
    }
  }
}

int app_msp_connection(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  const char *sidhex, *port_string, *local_port_string;
  once = cli_arg(parsed, "--once", NULL, NULL, NULL) == 0;

  if ( cli_arg(parsed, "--forward", &local_port_string, cli_uint, NULL) == -1
    || cli_arg(parsed, "sid", &sidhex, str_is_subscriber_id, NULL) == -1
    || cli_arg(parsed, "port", &port_string, cli_uint, NULL) == -1)
    return -1;
  
  struct mdp_sockaddr addr;
  bzero(&addr, sizeof addr);
  
  addr.port = atoi(port_string);
  saw_error=0;
  
  if (sidhex && *sidhex){
    if (str_to_sid_t(&addr.sid, sidhex) == -1)
      return WHY("str_to_sid_t() failed");
  }
  
  int ret=-1;
  struct msp_sock *sock = NULL;
  
  mdp_sock.poll.fd = mdp_socket();
  if (mdp_sock.poll.fd==-1)
    goto end;
  watch(&mdp_sock);
  
  set_nonblock(STDIN_FILENO);
  set_nonblock(STDOUT_FILENO);
  bzero(&ip_addr, sizeof ip_addr);
  
  if (local_port_string){
    ip_addr.addrlen = sizeof(ip_addr.inet);
    ip_addr.inet.sin_family = AF_INET;
    ip_addr.inet.sin_port = htons(atoi(local_port_string));
    ip_addr.inet.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  }
  
  if (sidhex && *sidhex){
    if (local_port_string){
      remote_addr = addr;
      listen_alarm.poll.fd = esocket(PF_INET, SOCK_STREAM, 0);
      if (listen_alarm.poll.fd==-1)
	goto end;
      if (socket_bind(listen_alarm.poll.fd, &ip_addr.addr, ip_addr.addrlen)==-1)
	goto end;
      if (socket_listen(listen_alarm.poll.fd, 0)==-1)
	goto end;
      watch(&listen_alarm);
      INFOF("- Forwarding from %s to %s:%d", alloca_socket_address(&ip_addr), alloca_tohex_sid_t(addr.sid), addr.port);
    }else{
      sock = msp_socket(mdp_sock.poll.fd);
      once = 1;
      struct connection *conn=alloc_connection(sock, STDIN_FILENO, io_poll, STDOUT_FILENO, io_poll);
      if (!conn)
	goto end;
      msp_set_handler(sock, msp_handler, conn);
      msp_set_remote(sock, addr);
      INFOF("- Connecting to %s:%d", alloca_tohex_sid_t(addr.sid), addr.port);
    }
  }else{
    sock = msp_socket(mdp_sock.poll.fd);
    msp_set_handler(sock, msp_listener, NULL);
    msp_set_local(sock, addr);
    
    // sock will be closed if listen fails
    if (msp_listen(sock)==-1)
      goto end;
    
    listener=sock;
    if (local_port_string){
      INFOF("- Forwarding from port %d to %s", addr.port, alloca_socket_address(&ip_addr));
    }else{
      once = 1;
      INFOF(" - Listening on port %d", addr.port);
    }
  }
  
  process_msp_asap();
  
  while(fd_poll()){
    ;
  }
  ret = saw_error;
  
end:
  listener=NULL;
  if (is_watching(&mdp_sock))
    unwatch(&mdp_sock);
  if (mdp_sock.poll.fd!=-1){
    msp_close_all(mdp_sock.poll.fd);
    mdp_close(mdp_sock.poll.fd);
  }
  if (listen_alarm.poll.fd !=-1 && is_watching(&listen_alarm))
    unwatch(&listen_alarm);
  if (listen_alarm.poll.fd!=-1)
    close(listen_alarm.poll.fd);
  unschedule(&mdp_sock);
  return ret;
}

