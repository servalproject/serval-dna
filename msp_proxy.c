
#include "serval.h"
#include "str.h"
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
struct msp_sock *listener=NULL;
struct mdp_sockaddr remote_addr;

static int try_send(struct connection *conn);
static void msp_poll(struct sched_ent *alarm);
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
  DEBUGF("Freeing connection %p", conn);
  free(conn);

  if (msp_socket_count()==0){
    DEBUGF("All sockets closed");
    unschedule(&mdp_sock);
    
    if (is_watching(&mdp_sock))
      unwatch(&mdp_sock);
  }
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
    
    if (!conn->out->limit){
      free_connection(conn);
    }
    
    return 0;
  }
  
  if (state&MSP_STATE_DATAOUT){
    try_send(conn);
    if (conn->in->limit<conn->in->capacity && !is_watching(&conn->alarm_in))
      watch(&conn->alarm_in);
  }
  return 0;
}

static int msp_listener(struct msp_sock *sock, msp_state_t state, const uint8_t *payload, size_t len, void *UNUSED(context))
{
  if (state & MSP_STATE_CLOSED)
    return 0;
  
  struct mdp_sockaddr remote;
  msp_get_remote_adr(sock, &remote);
  INFOF(" - New connection from %s:%d", alloca_tohex_sid_t(remote.sid), remote.port);
  
  struct connection *conn = alloc_connection(sock, STDIN_FILENO, io_poll, STDOUT_FILENO, io_poll);
  if (!conn)
    return -1;
    
  conn->sock = sock;
  watch(&conn->alarm_in);
  msp_set_handler(sock, msp_handler, conn);
  if (payload)
    return msp_handler(sock, state, payload, len, conn);
  
  // stop listening after the first incoming connection
  msp_close(listener);
  
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

static int try_send(struct connection *conn)
{
  if (!conn->in->limit)
    return 0;
  if (msp_send(conn->sock, conn->in->bytes, conn->in->limit)==-1)
    return 0;
  
  // if this packet was acceptted, clear the read buffer
  conn->in->limit = conn->in->position = 0;
  
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
	if (try_send(conn)){
	  // attempt to process this socket asap
	  mdp_sock.alarm = gettime_ms();
	  mdp_sock.deadline = mdp_sock.alarm+10;
	  unschedule(&mdp_sock);
	  schedule(&mdp_sock);
	}
	// stop reading input when the buffer is full
	if (conn->in->limit==conn->in->capacity){
	  unwatch(alarm);
	}
      }else{
	if (conn->in->limit)
	  unwatch(alarm);
	else
	  // EOF and no data in the buffer, just trigger our error handler
	  alarm->poll.revents|=POLLERR;
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
      conn->out->limit=0;
      conn->out->position=0;
      if (is_watching(alarm))
	unwatch(alarm);
    }
    
    if (conn->out->limit < conn->out->capacity){
      if (conn->sock){
	// make sure we try to process this socket soon for more data
	mdp_sock.alarm = gettime_ms();
	mdp_sock.deadline = mdp_sock.alarm+10;
	unschedule(&mdp_sock);
	schedule(&mdp_sock);
      }else{
	free_connection(conn);
      }
    }
  }
  
  if (alarm->poll.revents & (POLLHUP | POLLERR)) {
    // input has closed?
    if (conn->sock){
      struct mdp_sockaddr remote;
      msp_get_remote_adr(conn->sock, &remote);
      msp_shutdown(conn->sock);
      INFOF(" - Connection with %s:%d local shutdown", alloca_tohex_sid_t(remote.sid), remote.port);
    }
    
    if (is_watching(alarm))
      unwatch(alarm);
    close(alarm->poll.fd);
    alarm->poll.fd=-1;
    
    // attempt to process this msp socket asap
    mdp_sock.alarm = gettime_ms();
    mdp_sock.deadline = mdp_sock.alarm+10;
    unschedule(&mdp_sock);
    schedule(&mdp_sock);
  }
}

int app_msp_connection(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  const char *sidhex, *port_string;
  
  if ( cli_arg(parsed, "sid", &sidhex, str_is_subscriber_id, NULL) == -1
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
  
  sock = msp_socket(mdp_sock.poll.fd);
  if (sidhex && *sidhex){
    struct connection *conn=alloc_connection(sock, STDIN_FILENO, io_poll, STDOUT_FILENO, io_poll);
    if (!conn)
      goto end;
    msp_set_handler(sock, msp_handler, conn);
    msp_set_remote(sock, addr);
    INFOF("- Connecting to %s:%d", alloca_tohex_sid_t(addr.sid), addr.port);
  }else{
    msp_set_handler(sock, msp_listener, NULL);
    msp_set_local(sock, addr);
    
    // sock will be closed if listen fails
    if (msp_listen(sock)==-1)
      goto end;
    
    listener=sock;
    INFOF(" - Listening on port %d", addr.port);
  }
  
  // run msp_processing once to init alarm timer
  mdp_sock.poll.revents=0;
  msp_poll(&mdp_sock);
  
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
  unschedule(&mdp_sock);
  return ret;
}

