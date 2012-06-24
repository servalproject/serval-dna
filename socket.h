int	socket_bind(const char *name, int type, int reuse);
void	socket_setname(struct sockaddr_un *sockname, const char *name, socklen_t *len);
void	socket_done(const char *name);


