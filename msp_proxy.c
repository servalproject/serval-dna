
#include "serval.h"
#include "str.h"
#include "dataformats.h"
#include "mdp_client.h"
#include "msp_client.h"

struct buffer{
  size_t position;
  size_t limit;
  size_t capacity;
  uint8_t bytes[];
};

struct connection{
  struct msp_sock *sock;
  struct buffer *in;
  struct buffer *out;
};

struct connection *stdio_connection=NULL;
struct msp_sock *listener=NULL;

static void msp_poll(struct sched_ent *alarm);
static void stdin_poll(struct sched_ent *alarm);
static void stdout_poll(struct sched_ent *alarm);

struct profile_total mdp_sock_stats={
  .name="msp_poll"
};
struct sched_ent mdp_sock={
  .function = msp_poll,
  .stats = &mdp_sock_stats,
};

struct profile_total stdin_stats={
  .name="stdin_poll"
};
struct sched_ent stdin_alarm={
  .function = stdin_poll,
  .stats = &stdin_stats,
};

struct profile_total stdout_stats={
  .name="stdout_poll"
};
struct sched_ent stdout_alarm={
  .function = stdout_poll,
  .stats = &stdout_stats,
};

static struct connection *alloc_connection()
{
  struct connection *conn = emalloc_zero(sizeof(struct connection));
  if (!conn)
    return NULL;
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
  if (conn->in)
    free(conn->in);
  if (conn->out)
    free(conn->out);
  free(conn);
}

static int msp_handler(struct msp_sock *sock, msp_state_t state, const uint8_t *payload, size_t len, void *context)
{
  struct connection *conn = context;
  DEBUGF("Handler, state %d, payload len %zd", state, len);
  
  if (payload && len){
    dump("incoming payload", payload, len);
    if (conn->out->capacity < len + conn->out->limit){
      DEBUGF("Insufficient space len %zd, capacity %zd, limit %zd", len, conn->out->capacity, conn->out->limit);
      return -1;
    }
    if (conn->out->limit==0){
      watch(&stdout_alarm);
      INFOF("Watching stdout");
    }
    bcopy(payload, &conn->out->bytes[conn->out->limit], len);
    conn->out->limit+=len;
  }
  
  if (state & MSP_STATE_CLOSED){
    struct mdp_sockaddr remote;
    msp_get_remote_adr(sock, &remote);
    INFOF(" - Connection with %s:%d closed", alloca_tohex_sid_t(remote.sid), remote.port);
    
    if (conn == stdio_connection){
      stdio_connection->sock=NULL;
    }else{
      free_connection(conn);
    }
    
    unschedule(&mdp_sock);
    
    if (mdp_sock.poll.events){
      unwatch(&mdp_sock);
      mdp_sock.poll.events=0;
      INFOF("Unwatching mdp socket");
    }
    mdp_close(mdp_sock.poll.fd);
    mdp_sock.poll.fd=-1;
    return 0;
  }
  
  if (state & MSP_STATE_SHUTDOWN_REMOTE){
    struct mdp_sockaddr remote;
    msp_get_remote_adr(sock, &remote);
    INFOF(" - Connection with %s:%d remote shutdown", alloca_tohex_sid_t(remote.sid), remote.port);
  }
  
  return 0;
}

static int msp_listener(struct msp_sock *sock, msp_state_t state, const uint8_t *payload, size_t len, void *UNUSED(context))
{
  struct mdp_sockaddr remote;
  msp_get_remote_adr(sock, &remote);
  INFOF(" - New connection from %s:%d", alloca_tohex_sid_t(remote.sid), remote.port);
  
  struct connection *conn = alloc_connection();
  if (!conn)
    return -1;
  conn->sock = sock;
  if (!stdio_connection){
    stdio_connection=conn;
    watch(&stdin_alarm);
    INFOF("Watching stdin");
  }
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

static void stdin_poll(struct sched_ent *alarm)
{
  INFOF("Poll stdin, %d", alarm->poll.revents);
  if (alarm->poll.revents & POLLIN) {
    if (!stdio_connection){
      unwatch(alarm);
      INFOF("Unwatching stdin");
      return;
    }
    
    size_t remaining = stdio_connection->in->capacity - stdio_connection->in->limit;
    if (remaining>0){
      ssize_t r = read(alarm->poll.fd, 
	stdio_connection->in->bytes + stdio_connection->in->limit,
	remaining);
      INFOF("Read %zd from stdin %d, %d", r, alarm->poll.revents, errno);
      if (r>0){
	dump("stdin",stdio_connection->in->bytes + stdio_connection->in->limit, r);
	
	stdio_connection->in->limit+=r;
	
	if (msp_send(stdio_connection->sock, stdio_connection->in->bytes, stdio_connection->in->limit)!=-1){
	  // if this packet was acceptted, clear the read buffer
	  stdio_connection->in->limit = stdio_connection->in->position = 0;
	  // attempt to process this socket asap
	  mdp_sock.alarm = gettime_ms();
	  mdp_sock.deadline = mdp_sock.alarm+10;
	  unschedule(&mdp_sock);
	  schedule(&mdp_sock);
	}
	
	// stop reading input when the buffer is full
	if (stdio_connection->in->limit==stdio_connection->in->capacity){
	  unwatch(alarm);
	  INFOF("Unwatching stdin");
	}
      }else{
	// EOF, just trigger our error handler
	alarm->poll.revents|=POLLERR;
      }
    }
  }
  
  if (alarm->poll.revents & (POLLHUP | POLLERR)) {
    // input has closed?
    struct mdp_sockaddr remote;
    msp_get_remote_adr(stdio_connection->sock, &remote);
    msp_shutdown(stdio_connection->sock);
    unwatch(alarm);
    INFOF(" - Connection with %s:%d local shutdown", alloca_tohex_sid_t(remote.sid), remote.port);
    // attempt to process this socket asap
    mdp_sock.alarm = gettime_ms();
    mdp_sock.deadline = mdp_sock.alarm+10;
    unschedule(&mdp_sock);
    schedule(&mdp_sock);
  }
}

static void stdout_poll(struct sched_ent *alarm)
{
  if (alarm->poll.revents & POLLOUT) {
    if (!stdio_connection){
      unwatch(alarm);
      INFOF("Unwatching stdout");
      return;
    }
    // try to write some data
    size_t data = stdio_connection->out->limit-stdio_connection->out->position;
    if (data>0){
      ssize_t r = write(alarm->poll.fd, 
	stdio_connection->out->bytes+stdio_connection->out->position,
	data);
      INFOF("Wrote %zd to stdout", r);
      if (r > 0)
	stdio_connection->out->position+=r;
    }
    
    // if the buffer is empty now, reset it and unwatch the handle
    if (stdio_connection->out->position==stdio_connection->out->limit){
      stdio_connection->out->limit=0;
      stdio_connection->out->position=0;
      unwatch(alarm);
      INFOF("Unwatching stdout");
    }
    
    if (stdio_connection->out->limit < stdio_connection->out->capacity){
      // TODO try to get more data from the socket
    }
  }
  
  if (alarm->poll.revents & (POLLHUP | POLLERR)) {
    unwatch(alarm);
    INFOF("Unwatching stdout");
    // Um, quit?
  }
}

int app_msp_connection(const struct cli_parsed *parsed, struct cli_context *UNUSED(context))
{
  const char *sidhex, *port_string;
  
  if (cli_arg(parsed, "sid", &sidhex, str_is_subscriber_id, NULL) == -1)
    return -1;
  if (cli_arg(parsed, "port", &port_string, cli_uint, NULL) == -1)
    return -1;
  
  struct mdp_sockaddr addr;
  bzero(&addr, sizeof addr);
  
  addr.port = atoi(port_string);
  
  if (sidhex && *sidhex){
    if (str_to_sid_t(&addr.sid, sidhex) == -1)
      return WHY("str_to_sid_t() failed");
  }
  
  int ret=-1;
  struct msp_sock *sock = NULL;
  
  mdp_sock.poll.fd = mdp_socket();
  if (mdp_sock.poll.fd==-1)
    goto end;
  mdp_sock.poll.events = POLLIN;
  watch(&mdp_sock);
  INFOF("Watching mdp socket");
  
  set_nonblock(STDIN_FILENO);
  set_nonblock(STDOUT_FILENO);
  
  stdin_alarm.poll.fd=STDIN_FILENO;
  stdin_alarm.poll.events=POLLIN;
  
  stdout_alarm.poll.fd=STDOUT_FILENO;
  stdout_alarm.poll.events=POLLOUT;
  
  sock = msp_socket(mdp_sock.poll.fd);
  if (sidhex && *sidhex){
    stdio_connection = alloc_connection();
    if (!stdio_connection)
      goto end;
    stdio_connection->sock = sock;
    msp_set_handler(sock, msp_handler, stdio_connection);
    msp_set_remote(sock, addr);
    INFOF("Set remote %s:%d", alloca_tohex_sid_t(addr.sid), addr.port);
    
    // note we only watch these stdio handles when we have space / bytes in our buffers
    watch(&stdin_alarm);
    INFOF("Watching stdin");
  }else{
    msp_set_handler(sock, msp_listener, NULL);
    msp_set_local(sock, addr);
    
    // sock will be closed if listen fails
    if (msp_listen(sock)==-1)
      goto end;
    
    listener=sock;
    INFOF(" - Listening on port %d", addr.port);
  }
  
  while(fd_poll()){
    ;
  }
  ret=0;
  
end:
  listener=NULL;
  if (mdp_sock.poll.fd>=0){
    msp_close_all(mdp_sock.poll.fd);
    if (mdp_sock.poll.events){
      unwatch(&mdp_sock);
      INFOF("Unwatching mdp socket");
    }
    mdp_close(mdp_sock.poll.fd);
  }
  unschedule(&mdp_sock);
  free_connection(stdio_connection);
  stdio_connection=NULL;
  return ret;
}

