#ifndef __CCOIN_NET_ASOCKET_H__
#define __CCOIN_NET_ASOCKET_H__

#include <stdbool.h>

struct asocket_cfg;
struct asocket_opt;
struct aserver_cfg;
struct const_buffer;
struct event_base;
struct event;

struct asocket {
	int		fd;
	bool		error;
	bool		connecting;

	unsigned long long bytes_read;
	unsigned long long bytes_written;

	struct event	*ev;		// Read events

	struct event	*write_ev;	// Write events
	clist		*write_q;	// of struct buffer
	unsigned int	write_partial;

	unsigned char	addr[16];	// Remote peer
	bool		is_v4;

	char		addr_str[64];

	const struct asocket_cfg *cfg;	// Static configuration
	const struct asocket_opt *opt;	// Connect() options
};

struct asocket_cfg {
	struct event_base *eb;
	void		*priv;

	void		(*as_close)(struct asocket *, void *, bool had_err);
	void		(*as_error)(struct asocket *, void *, int err);
	void		(*as_end)(struct asocket *, void *);

	void		(*as_connect)(struct asocket *, void *);
	void		(*as_data)(struct asocket *, void *, const struct const_buffer *);
	void		(*as_drain)(struct asocket *, void *);
};

struct asocket_opt {
	const char	*host;
	const char	*port;
	int		family;
};

struct aserver {
	struct asocket	sock;

	const struct aserver_cfg *cfg;	// Static configuration
};

struct aserver_cfg {
	struct event_base *eb;
	void		*priv;

	void		(*as_close)(struct asocket *, void *, bool had_err);
	void		(*as_error)(struct asocket *, void *, int err);

	void		(*as_accepted)(struct asocket *, void *);
	void		(*as_listening)(struct asocket *, void *);
};

extern void asocket_init(struct asocket *as, const struct asocket_cfg *cfg);
extern void asocket_free(struct asocket *as);
extern void asocket_freep(void *p);
extern bool asocket_connect(struct asocket *as, const struct asocket_opt *opt);
extern bool asocket_write(struct asocket *as, const void *data,size_t data_len);
extern void asocket_close(struct asocket *as);
extern size_t asocket_writeq_sz(const struct asocket *as);

extern void aserver_init(struct aserver *srv, const struct aserver_cfg *cfg,
			 const struct asocket_cfg *sock_cfg);
extern void aserver_free(struct aserver *srv);
extern void aserver_freep(void *p);

#endif // __CCOIN_NET_ASOCKET_H__
