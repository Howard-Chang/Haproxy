#define _GNU_SOURCE

#include <errno.h>

#include <common/splice.h>
#include <types/cuju_ft.h>
#include <types/global.h>
#include <types/fd.h>

#include <proto/fd.h>
#include <proto/connection.h>
#include <proto/proto_tcp.h>
#include <proto/stream_interface.h>
#include <sys/sendfile.h>

#include <sys/shm.h>
#include <fcntl.h> 
#include <libs/soccr.h>
#include <types/tcp_repair.h>

#if USING_SOCCR_LOG
unsigned int log_level = 0;
static void (*log)(unsigned int loglevel, const char *format, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)));
extern unsigned int log_level;
#define loge(msg, ...) do { if (log && (log_level >= SOCCR_LOG_ERR)) log(SOCCR_LOG_ERR, "Error (%s:%d): " msg, __FILE__, __LINE__, ##__VA_ARGS__); } while (0)
#define logerr(msg, ...) loge(msg ": %s\n", ##__VA_ARGS__, strerror(errno))
#define logd(msg, ...) do { if (log && (log_level >= SOCCR_LOG_DBG)) log(SOCCR_LOG_DBG, "Debug: " msg, ##__VA_ARGS__); } while (0)
#else 
#define loge(msg, ...)
#define logerr(msg, ...)
#define logd(msg, ...)
#endif

int restore_sockaddr(union libsoccr_addr *sa,
		int family, u32 pb_port, u32 *pb_addr, u32 ifindex)
{
	BUILD_BUG_ON(sizeof(sa->v4.sin_addr.s_addr) > PB_ALEN_INET * sizeof(u32));
	BUILD_BUG_ON(sizeof(sa->v6.sin6_addr.s6_addr) > PB_ALEN_INET6 * sizeof(u32));

	memzero(sa, sizeof(*sa));

	if (family == AF_INET) {
		sa->v4.sin_family = AF_INET;
		sa->v4.sin_port = htons(pb_port);
		memcpy(&sa->v4.sin_addr.s_addr, pb_addr, sizeof(sa->v4.sin_addr.s_addr));
		return sizeof(sa->v4);
	}

	if (family == AF_INET6) {
		sa->v6.sin6_family = AF_INET6;
		sa->v6.sin6_port = htons(pb_port);
		memcpy(sa->v6.sin6_addr.s6_addr, pb_addr, sizeof(sa->v6.sin6_addr.s6_addr));

		/* Here although the struct member is called scope_id, the
		 * kernel really wants ifindex. See
		 * /net/ipv6/af_inet6.c:inet6_bind for details.
		 */
		sa->v6.sin6_scope_id = ifindex;
		return sizeof(sa->v6);
	}

	//BUG();
	return -1;
}


int tcp_repair_on(int fd)
{
	int ret, aux = 1;

	ret = setsockopt(fd, SOL_TCP, TCP_REPAIR, &aux, sizeof(aux));
	if (ret < 0)
		printf("Can't turn TCP repair mode ON");

	return ret;
}

int tcp_repair_off(int fd)
{
	int aux = 0, ret;

	ret = setsockopt(fd, SOL_TCP, TCP_REPAIR, &aux, sizeof(aux));
	if (ret < 0)
		printf("Failed to turn off repair mode on socket");

	return ret;
}


int set_queue_seq(struct libsoccr_sk *sk, int queue, __u32 seq)
{
	logd("\tSetting %d queue seq to %u\n", queue, seq);

	if (setsockopt(sk->fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue)) < 0) {
		logerr("Can't set repair queue");
		return -1;
	}

	if (setsockopt(sk->fd, SOL_TCP, TCP_QUEUE_SEQ, &seq, sizeof(seq)) < 0) {
		logerr("Can't set queue seq");
		return -1;
	}

	return 0;
}

int libsoccr_restore_queue_HA(struct libsoccr_sk *sk, struct sk_data_info *data, unsigned data_size,
		int queue, char *buf)
{
	if (!buf)
		return 0;

	if (!data || data_size < SOCR_DATA_MIN_SIZE)
		return -1;

	if (queue == TCP_RECV_QUEUE) {
		if (!data->sk_data.inq_len)
			return 0;
		return send_queue(sk, TCP_RECV_QUEUE, buf, data->sk_data.inq_len);
	}

	if (queue == TCP_SEND_QUEUE) {
		__u32 len, ulen;

		/*
		 * All data in a write buffer can be divided on two parts sent
		 * but not yet acknowledged data and unsent data.
		 * The TCP stack must know which data have been sent, because
		 * acknowledgment can be received for them. These data must be
		 * restored in repair mode.
		 */
		ulen = data->sk_data.unsq_len;
		len = data->sk_data.outq_len - ulen;
		if (len && send_queue(sk, TCP_SEND_QUEUE, buf, len))
			return -2;

		if (ulen) {
			/*
			 * The second part of data have never been sent to outside, so
			 * they can be restored without any tricks.
			 */
			tcp_repair_off(sk->fd);
			if (__send_queue(sk, TCP_SEND_QUEUE, buf + len, ulen))
				return -3;
			if (tcp_repair_on(sk->fd))
				return -4;
		}

		return 0;
	}

	return -5;
}


int restore_fin_in_snd_queue(int sk, int acked)
{
	int queue = TCP_SEND_QUEUE;
	int ret;

	/*
	 * If TCP_SEND_QUEUE is set, a fin packet will be
	 * restored as a sent packet.
	 */
	if (acked &&
	    setsockopt(sk, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue)) < 0) {
		logerr("Can't set repair queue");
		return -1;
	}

	ret = shutdown(sk, SHUT_WR);
	if (ret < 0)
		logerr("Unable to shut down a socket");

	queue = TCP_NO_QUEUE;
	if (acked &&
	    setsockopt(sk, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue)) < 0) {
		logerr("Can't set repair queue");
		return -1;
	}

	return ret;
}

int send_fin_HA(struct libsoccr_sk *sk, struct sk_data_info *data,
		unsigned data_size, uint8_t flags)
{
	uint32_t src_v4 = sk->src_addr->v4.sin_addr.s_addr;
	uint32_t dst_v4 = sk->dst_addr->v4.sin_addr.s_addr;
	int ret, exit_code = -1, family;
	char errbuf[LIBNET_ERRBUF_SIZE];
	int mark = SOCCR_MARK;
	int libnet_type;
	libnet_t *l;

	family = sk->dst_addr->sa.sa_family;

	if (family == AF_INET6 && ipv6_addr_mapped(sk->dst_addr)) {
		/* TCP over IPv4 */
		family = AF_INET;
		dst_v4 = sk->dst_addr->v6.sin6_addr.s6_addr32[3];
		src_v4 = sk->src_addr->v6.sin6_addr.s6_addr32[3];
	}

	if (family == AF_INET6)
		libnet_type = LIBNET_RAW6;
	else
		libnet_type = LIBNET_RAW4;

	l = libnet_init(
		libnet_type,		/* injection type */
		NULL,			/* network interface */
		errbuf);		/* errbuf */
	if (l == NULL) {
		loge("libnet_init failed (%s)\n", errbuf);
		return -1;
	}

	if (setsockopt(l->fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark))) {
		logerr("Can't set SO_MARK (%d) for socket\n", mark);
		goto err;
	}

	ret = libnet_build_tcp(
		ntohs(sk->dst_addr->v4.sin_port),		/* source port */
		ntohs(sk->src_addr->v4.sin_port),		/* destination port */
		data->sk_data.inq_seq,			/* sequence number */
		data->sk_data.outq_seq - data->sk_data.outq_len,	/* acknowledgement num */
		flags,				/* control flags */
		data->sk_data.rcv_wnd,			/* window size */
		0,				/* checksum */
		10,				/* urgent pointer */
		LIBNET_TCP_H + 20,		/* TCP packet size */
		NULL,				/* payload */
		0,				/* payload size */
		l,				/* libnet handle */
		0);				/* libnet id */
	if (ret == -1) {
		loge("Can't build TCP header: %s\n", libnet_geterror(l));
		goto err;
	}

	if (family == AF_INET6) {
		struct libnet_in6_addr src, dst;

		memcpy(&dst, &sk->dst_addr->v6.sin6_addr, sizeof(dst));
		memcpy(&src, &sk->src_addr->v6.sin6_addr, sizeof(src));

		ret = libnet_build_ipv6(
			0, 0,
			LIBNET_TCP_H,	/* length */
			IPPROTO_TCP,	/* protocol */
			64,		/* hop limit */
			dst,		/* source IP */
			src,		/* destination IP */
			NULL,		/* payload */
			0,		/* payload size */
			l,		/* libnet handle */
			0);		/* libnet id */
	} else if (family == AF_INET)
		ret = libnet_build_ipv4(
			LIBNET_IPV4_H + LIBNET_TCP_H + 20,	/* length */
			0,			/* TOS */
			242,			/* IP ID */
			0,			/* IP Frag */
			64,			/* TTL */
			IPPROTO_TCP,		/* protocol */
			0,			/* checksum */
			dst_v4,			/* source IP */
			src_v4,			/* destination IP */
			NULL,			/* payload */
			0,			/* payload size */
			l,			/* libnet handle */
			0);			/* libnet id */
	else {
		loge("Unknown socket family\n");
		goto err;
	}
	if (ret == -1) {
		loge("Can't build IP header: %s\n", libnet_geterror(l));
		goto err;
	}

	ret = libnet_write(l);
	if (ret == -1) {
		loge("Unable to send a fin packet: %s\n", libnet_geterror(l));
		goto err;
	}

	exit_code = 0;
err:
	libnet_destroy(l);
	return exit_code;
}

int send_queue(struct libsoccr_sk *sk, int queue, char *buf, __u32 len)
{
	logd("\tRestoring TCP %d queue data %u bytes\n", queue, len);

	if (setsockopt(sk->fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue)) < 0) {
		logerr("Can't set repair queue");
		return -1;
	}

	return __send_queue(sk, queue, buf, len);
}


int __send_queue(struct libsoccr_sk *sk, int queue, char *buf, __u32 len)
{
	int ret, err = -1, max_chunk;
	int off;

	max_chunk = len;
	off = 0;

	do {
		int chunk = len;

		if (chunk > max_chunk)
			chunk = max_chunk;

		ret = send(sk->fd, buf + off, chunk, 0);
		if (ret <= 0) {
			if (max_chunk > 1024) {
				/*
				 * Kernel not only refuses the whole chunk,
				 * but refuses to split it into pieces too.
				 *
				 * When restoring recv queue in repair mode
				 * kernel doesn't try hard and just allocates
				 * a linear skb with the size we pass to the
				 * system call. Thus, if the size is too big
				 * for slab allocator, the send just fails
				 * with ENOMEM.
				 *
				 * In any case -- try smaller chunk, hopefully
				 * there's still enough memory in the system.
				 */
				max_chunk >>= 1;
				continue;
			}

			logerr("Can't restore %d queue data (%d), want (%d:%d:%d)",
				  queue, ret, chunk, len, max_chunk);
			goto err;
		}
		off += ret;
		len -= ret;
	} while (len);

	err = 0;
err:
	return err;
}


int ipv6_addr_mapped(union libsoccr_addr *addr)
{
	return (addr->v6.sin6_addr.s6_addr32[2] == htonl(0x0000ffff));
}


int libsoccr_set_sk_data_noq_conn(struct libsoccr_sk *sk,
		struct sk_data_info *data, unsigned int data_size)
{
	struct tcp_repair_opt opts[4];
	int addr_size, mstate;
	int onr = 0;
	__u32 seq;

	if (!data || data_size < SOCR_DATA_MIN_SIZE) {
		printf("Invalid input parameters\n");
		return -1;
	}

	if (!sk->dst_addr || !sk->src_addr) {
		printf("Destination or/and source addresses aren't set\n");
		return -1;
	}

	mstate = 1 << data->sk_data.state;

	if (data->sk_data.state == TCP_LISTEN) {
		printf("Unable to handle listen sockets\n");
		return -1;
	}

	if (sk->src_addr->sa.sa_family == AF_INET)
		addr_size = sizeof(sk->src_addr->v4);
	else
		addr_size = sizeof(sk->src_addr->v6);

#if 0
	if (bind(sk->fd, &sk->src_addr->sa, addr_size)) {
		printf("Can't bind inet socket back");
		return -1;
	}
#endif	

	if (mstate & (RCVQ_FIRST_FIN | RCVQ_SECOND_FIN))
		data->sk_data.inq_seq--;

	/* outq_seq is adjusted due to not accointing the fin packet */
	if (mstate & (SNDQ_FIRST_FIN | SNDQ_SECOND_FIN))
		data->sk_data.outq_seq--;

	if (set_queue_seq(sk, TCP_RECV_QUEUE,
				data->sk_data.inq_seq - data->sk_data.inq_len))
		return -2;

	seq = data->sk_data.outq_seq - data->sk_data.outq_len;
	if (data->sk_data.state == TCP_SYN_SENT)
		seq--;

	if (set_queue_seq(sk, TCP_SEND_QUEUE, seq))
		return -3;

	if (sk->dst_addr->sa.sa_family == AF_INET)
		addr_size = sizeof(sk->dst_addr->v4);
	else
		addr_size = sizeof(sk->dst_addr->v6);

	if (data->sk_data.state == TCP_SYN_SENT && tcp_repair_off(sk->fd))
		return -1;

	if (connect(sk->fd, &sk->dst_addr->sa, addr_size) == -1 &&
						errno != EINPROGRESS) {
		printf("Can't connect inet socket back");
		return -1;
	}

	if (data->sk_data.state == TCP_SYN_SENT && tcp_repair_on(sk->fd))
		return -1;

	printf("\tRestoring TCP options\n");

	if (data->sk_data.opt_mask & TCPI_OPT_SACK) {
		printf("\t\tWill turn SAK on\n");
		opts[onr].opt_code = TCPOPT_SACK_PERM;
		opts[onr].opt_val = 0;
		onr++;
	}

	if (data->sk_data.opt_mask & TCPI_OPT_WSCALE) {
		printf("\t\tWill set snd_wscale to %u\n", data->sk_data.snd_wscale);
		printf("\t\tWill set rcv_wscale to %u\n", data->sk_data.rcv_wscale);
		opts[onr].opt_code = TCPOPT_WINDOW;
		opts[onr].opt_val = data->sk_data.snd_wscale + (data->sk_data.rcv_wscale << 16);
		onr++;
	}

	if (data->sk_data.opt_mask & TCPI_OPT_TIMESTAMPS) {
		printf("\t\tWill turn timestamps on\n");
		opts[onr].opt_code = TCPOPT_TIMESTAMP;
		opts[onr].opt_val = 0;
		onr++;
	}

	printf("Will set mss clamp to %u\n", data->sk_data.mss_clamp);
	opts[onr].opt_code = TCPOPT_MAXSEG;
	opts[onr].opt_val = data->sk_data.mss_clamp;
	onr++;

	if (data->sk_data.state != TCP_SYN_SENT &&
	    setsockopt(sk->fd, SOL_TCP, TCP_REPAIR_OPTIONS,
				opts, onr * sizeof(struct tcp_repair_opt)) < 0) {
		printf("Can't repair options");
		return -2;
	}

	if (data->sk_data.opt_mask & TCPI_OPT_TIMESTAMPS) {
		if (setsockopt(sk->fd, SOL_TCP, TCP_TIMESTAMP,
				&data->sk_data.timestamp, sizeof(data->sk_data.timestamp)) < 0) {
			logerr("Can't set timestamp");
			return -3;
		}
	}

	return 0;
}

int libsoccr_restore_conn(struct sk_data_info* data, 
						  unsigned int data_size)
{
	int mstate = 1 << data->sk_data.state;

	if (libsoccr_set_sk_data_noq_conn(data->libsoccr_sk, data, data_size))
		return -1;


	if (libsoccr_restore_queue_HA(data->libsoccr_sk, data, sizeof(*data), TCP_RECV_QUEUE, data->libsoccr_sk->recv_queue))
		return -1;

	if (libsoccr_restore_queue_HA(data->libsoccr_sk, data, sizeof(*data), TCP_SEND_QUEUE, data->libsoccr_sk->send_queue))
		return -1;

	if (data->sk_data.flags & SOCCR_FLAGS_WINDOW) {
		struct tcp_repair_window wopt = {
			.snd_wl1 = data->sk_data.snd_wl1,
			.snd_wnd = data->sk_data.snd_wnd,
			.max_window = data->sk_data.max_window,
			.rcv_wnd = data->sk_data.rcv_wnd,
			.rcv_wup = data->sk_data.rcv_wup,
		};

		if (mstate & (RCVQ_FIRST_FIN | RCVQ_SECOND_FIN)) {
			wopt.rcv_wup--;
			wopt.rcv_wnd++;
		}

		if (setsockopt(data->libsoccr_sk->fd, SOL_TCP, TCP_REPAIR_WINDOW, &wopt, sizeof(wopt))) {
			logerr("Unable to set window parameters");
			return -1;
		}
	}

	/*
	 * To restore a half closed sockets, fin packets has to be restored in
	 * recv and send queues. Here shutdown() is used to restore a fin
	 * packet in the send queue and a fake fin packet is send to restore it
	 * in the recv queue.
	 */
	if (mstate & SNDQ_FIRST_FIN)
		restore_fin_in_snd_queue(data->libsoccr_sk->fd, mstate & SNDQ_FIN_ACKED);

	/* Send a fin packet to the socket to restore it in a receive queue. */
	if (mstate & (RCVQ_FIRST_FIN | RCVQ_SECOND_FIN))
		if (send_fin_HA(data->libsoccr_sk, data, data_size, TH_ACK | TH_FIN) < 0)
			return -1;

	if (mstate & SNDQ_SECOND_FIN)
		restore_fin_in_snd_queue(data->libsoccr_sk->fd, mstate & SNDQ_FIN_ACKED);

	if (mstate & RCVQ_FIN_ACKED)
		data->sk_data.inq_seq++;

	if (mstate & SNDQ_FIN_ACKED) {
		data->sk_data.outq_seq++;
		if (send_fin_HA(data->libsoccr_sk, data, data_size, TH_ACK) < 0)
			return -1;
	}


	return 0;
}

/*******************TCP repair by Howard****************/
void free_buf(dt_info* buf)
{
    free(buf->recv_queue);
    free(buf->send_queue);
    free(buf);
}


int restore_sockaddr_HA(union libsoccr_addr *sa,
		int family, uint16_t pb_port, u32 *pb_addr, u32 ifindex)
{
	memset(sa, 0, sizeof(*sa));
	if (family == AF_INET) {
		sa->v4.sin_family = AF_INET;
		sa->v4.sin_port = pb_port;
		memcpy(&sa->v4.sin_addr.s_addr, pb_addr, sizeof(sa->v4.sin_addr.s_addr));
		return sizeof(sa->v4);
	}
	return -1;
}

int libsoccr_set_sk_data_noq_HA(struct libsoccr_sk *sk,
		dt_info *data, unsigned data_size)
{
	struct tcp_repair_opt opts[4];
	int addr_size, mstate;
	int onr = 0;
	__u32 seq;

	if (!data || data_size < SOCR_DATA_MIN_SIZE) {
		printf("Invalid input parameters\n");
		return -1;
	}

	if (!sk->dst_addr || !sk->src_addr) {
		printf("Destination or/and source addresses aren't set\n");
		return -1;
	}

	mstate = 1 << data->sk_hd.state;

	if (data->sk_hd.state == TCP_LISTEN) {
		printf("Unable to handle listen sockets\n");
		return -1;
	}

	if (sk->src_addr->sa.sa_family == AF_INET)
		addr_size = sizeof(sk->src_addr->v4);
	else
		addr_size = sizeof(sk->src_addr->v6);

	if (bind(sk->fd, &sk->src_addr->sa, addr_size)) {
		printf("Can't bind inet socket back");
		return -1;
	}

	if (mstate & (RCVQ_FIRST_FIN | RCVQ_SECOND_FIN))
		data->sk_hd.inq_seq--;

	/* outq_seq is adjusted due to not accointing the fin packet */
	if (mstate & (SNDQ_FIRST_FIN | SNDQ_SECOND_FIN))
		data->sk_hd.outq_seq--;

	if (set_queue_seq(sk, TCP_RECV_QUEUE,
				data->sk_hd.inq_seq - data->sk_hd.inq_len))
		return -2;

	seq = data->sk_hd.outq_seq - data->sk_hd.outq_len;
	if (data->sk_hd.state == TCP_SYN_SENT)
		seq--;

	if (set_queue_seq(sk, TCP_SEND_QUEUE, seq))
		return -3;

	if (sk->dst_addr->sa.sa_family == AF_INET)
		addr_size = sizeof(sk->dst_addr->v4);
	else
		addr_size = sizeof(sk->dst_addr->v6);

	if (data->sk_hd.state == TCP_SYN_SENT && tcp_repair_off(sk->fd))
		return -1;

	if (connect(sk->fd, &sk->dst_addr->sa, addr_size) == -1 &&
						errno != EINPROGRESS) {
		printf("Can't connect inet socket back");
		return -1;
	}

	if (data->sk_hd.state == TCP_SYN_SENT && tcp_repair_on(sk->fd))
		return -1;

	printf("\tRestoring TCP options\n");

	if (data->sk_hd.opt_mask & TCPI_OPT_SACK) {
		printf("\t\tWill turn SAK on\n");
		opts[onr].opt_code = TCPOPT_SACK_PERM;
		opts[onr].opt_val = 0;
		onr++;
	}

	if (data->sk_hd.opt_mask & TCPI_OPT_WSCALE) {
		printf("\t\tWill set snd_wscale to %u\n", data->sk_hd.snd_wscale);
		printf("\t\tWill set rcv_wscale to %u\n", data->sk_hd.rcv_wscale);
		opts[onr].opt_code = TCPOPT_WINDOW;
		opts[onr].opt_val = data->sk_hd.snd_wscale + (data->sk_hd.rcv_wscale << 16);
		onr++;
	}

	if (data->sk_hd.opt_mask & TCPI_OPT_TIMESTAMPS) {
		printf("\t\tWill turn timestamps on\n");
		opts[onr].opt_code = TCPOPT_TIMESTAMP;
		opts[onr].opt_val = 0;
		onr++;
	}

	printf("Will set mss clamp to %u\n", data->sk_hd.mss_clamp);
	opts[onr].opt_code = TCPOPT_MAXSEG;
	opts[onr].opt_val = data->sk_hd.mss_clamp;
	onr++;

	if (data->sk_hd.state != TCP_SYN_SENT &&
	    setsockopt(sk->fd, SOL_TCP, TCP_REPAIR_OPTIONS,
				opts, onr * sizeof(struct tcp_repair_opt)) < 0) {
		printf("Can't repair options");
		return -2;
	}

	if (data->sk_hd.opt_mask & TCPI_OPT_TIMESTAMPS) {
		if (setsockopt(sk->fd, SOL_TCP, TCP_TIMESTAMP,
				&data->sk_hd.timestamp, sizeof(data->sk_hd.timestamp)) < 0) {
			logerr("Can't set timestamp");
			return -3;
		}
	}

	return 0;
}

int libsoccr_restore_queue_HAProxy(struct libsoccr_sk *sk, dt_info *data, unsigned data_size,
		int queue, char *buf)
{
	if (!buf)
		return 0;

	if (!data || data_size < SOCR_DATA_MIN_SIZE)
		return -1;

	if (queue == TCP_RECV_QUEUE) {
		if (!data->sk_hd.inq_len)
			return 0;
		return send_queue(sk, TCP_RECV_QUEUE, buf, data->sk_hd.inq_len);
	}

	if (queue == TCP_SEND_QUEUE) {
		__u32 len, ulen;

		/*
		 * All data in a write buffer can be divided on two parts sent
		 * but not yet acknowledged data and unsent data.
		 * The TCP stack must know which data have been sent, because
		 * acknowledgment can be received for them. These data must be
		 * restored in repair mode.
		 */
		ulen = data->sk_hd.unsq_len;
		len = data->sk_hd.outq_len - ulen;
		if (len && send_queue(sk, TCP_SEND_QUEUE, buf, len))
			return -2;

		if (ulen) {
			/*
			 * The second part of data have never been sent to outside, so
			 * they can be restored without any tricks.
			 */
			tcp_repair_off(sk->fd);
			if (__send_queue(sk, TCP_SEND_QUEUE, buf + len, ulen))
				return -3;
			if (tcp_repair_on(sk->fd))
				return -4;
		}

		return 0;
	}

	return -5;
}

int send_fin_HAProxy(struct libsoccr_sk *sk, dt_info *data,
		unsigned data_size, uint8_t flags)
{
	uint32_t src_v4 = sk->src_addr->v4.sin_addr.s_addr;
	uint32_t dst_v4 = sk->dst_addr->v4.sin_addr.s_addr;
	int ret, exit_code = -1, family;
	char errbuf[LIBNET_ERRBUF_SIZE];
	int mark = SOCCR_MARK;
	int libnet_type;
	libnet_t *l;

	family = sk->dst_addr->sa.sa_family;

	if (family == AF_INET6 && ipv6_addr_mapped(sk->dst_addr)) {
		/* TCP over IPv4 */
		family = AF_INET;
		dst_v4 = sk->dst_addr->v6.sin6_addr.s6_addr32[3];
		src_v4 = sk->src_addr->v6.sin6_addr.s6_addr32[3];
	}

	if (family == AF_INET6)
		libnet_type = LIBNET_RAW6;
	else
		libnet_type = LIBNET_RAW4;

	l = libnet_init(
		libnet_type,		/* injection type */
		NULL,			/* network interface */
		errbuf);		/* errbuf */
	if (l == NULL) {
		loge("libnet_init failed (%s)\n", errbuf);
		return -1;
	}

	if (setsockopt(l->fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark))) {
		logerr("Can't set SO_MARK (%d) for socket\n", mark);
		goto err;
	}

	ret = libnet_build_tcp(
		ntohs(sk->dst_addr->v4.sin_port),		/* source port */
		ntohs(sk->src_addr->v4.sin_port),		/* destination port */
		data->sk_hd.inq_seq,			/* sequence number */
		data->sk_hd.outq_seq - data->sk_hd.outq_len,	/* acknowledgement num */
		flags,				/* control flags */
		data->sk_hd.rcv_wnd,			/* window size */
		0,				/* checksum */
		10,				/* urgent pointer */
		LIBNET_TCP_H + 20,		/* TCP packet size */
		NULL,				/* payload */
		0,				/* payload size */
		l,				/* libnet handle */
		0);				/* libnet id */
	if (ret == -1) {
		loge("Can't build TCP header: %s\n", libnet_geterror(l));
		goto err;
	}

	if (family == AF_INET6) {
		struct libnet_in6_addr src, dst;

		memcpy(&dst, &sk->dst_addr->v6.sin6_addr, sizeof(dst));
		memcpy(&src, &sk->src_addr->v6.sin6_addr, sizeof(src));

		ret = libnet_build_ipv6(
			0, 0,
			LIBNET_TCP_H,	/* length */
			IPPROTO_TCP,	/* protocol */
			64,		/* hop limit */
			dst,		/* source IP */
			src,		/* destination IP */
			NULL,		/* payload */
			0,		/* payload size */
			l,		/* libnet handle */
			0);		/* libnet id */
	} else if (family == AF_INET)
		ret = libnet_build_ipv4(
			LIBNET_IPV4_H + LIBNET_TCP_H + 20,	/* length */
			0,			/* TOS */
			242,			/* IP ID */
			0,			/* IP Frag */
			64,			/* TTL */
			IPPROTO_TCP,		/* protocol */
			0,			/* checksum */
			dst_v4,			/* source IP */
			src_v4,			/* destination IP */
			NULL,			/* payload */
			0,			/* payload size */
			l,			/* libnet handle */
			0);			/* libnet id */
	else {
		loge("Unknown socket family\n");
		goto err;
	}
	if (ret == -1) {
		loge("Can't build IP header: %s\n", libnet_geterror(l));
		goto err;
	}

	ret = libnet_write(l);
	if (ret == -1) {
		loge("Unable to send a fin packet: %s\n", libnet_geterror(l));
		goto err;
	}

	exit_code = 0;
err:
	libnet_destroy(l);
	return exit_code;
}

int libsoccr_restore_HA(struct libsoccr_sk *sk,
		dt_info* data, unsigned data_size)
{
	int mstate = 1 << data->sk_hd.state;

	if (libsoccr_set_sk_data_noq_HA(sk, data, data_size))
		return -1;


	if (libsoccr_restore_queue_HAProxy(sk, data, sizeof(*data), TCP_RECV_QUEUE, data->recv_queue))
		return -1;

	if (libsoccr_restore_queue_HAProxy(sk, data, sizeof(*data), TCP_SEND_QUEUE, data->send_queue))
		return -1;

	if (data->sk_hd.flags & SOCCR_FLAGS_WINDOW) {
		struct tcp_repair_window wopt = {
			.snd_wl1 = data->sk_hd.snd_wl1,
			.snd_wnd = data->sk_hd.snd_wnd,
			.max_window = data->sk_hd.max_window,
			.rcv_wnd = data->sk_hd.rcv_wnd,
			.rcv_wup = data->sk_hd.rcv_wup,
		};

		if (mstate & (RCVQ_FIRST_FIN | RCVQ_SECOND_FIN)) {
			wopt.rcv_wup--;
			wopt.rcv_wnd++;
		}

		if (setsockopt(sk->fd, SOL_TCP, TCP_REPAIR_WINDOW, &wopt, sizeof(wopt))) {
			logerr("Unable to set window parameters");
			return -1;
		}
	}

	/*
	 * To restore a half closed sockets, fin packets has to be restored in
	 * recv and send queues. Here shutdown() is used to restore a fin
	 * packet in the send queue and a fake fin packet is send to restore it
	 * in the recv queue.
	 */
	if (mstate & SNDQ_FIRST_FIN)
		restore_fin_in_snd_queue(sk->fd, mstate & SNDQ_FIN_ACKED);

	/* Send a fin packet to the socket to restore it in a receive queue. */
	if (mstate & (RCVQ_FIRST_FIN | RCVQ_SECOND_FIN))
		if (send_fin_HAProxy(sk, data, data_size, TH_ACK | TH_FIN) < 0)
			return -1;

	if (mstate & SNDQ_SECOND_FIN)
		restore_fin_in_snd_queue(sk->fd, mstate & SNDQ_FIN_ACKED);

	if (mstate & RCVQ_FIN_ACKED)
		data->sk_hd.inq_seq++;

	if (mstate & SNDQ_FIN_ACKED) {
		data->sk_hd.outq_seq++;
		if (send_fin_HAProxy(sk, data, data_size, TH_ACK) < 0)
			return -1;
	}


	return 0;
}

void get_data(dt_info* data_info, char* tmp, prefix pre)
{
	int len = sizeof(prefix) + pre.conn_size*sizeof(struct sk_hd);
	int hd_idx = sizeof(prefix);
	//TODO: for loop to get tcp dump data
	for(int i=0; i < pre.conn_size; i++)
	{
		memcpy(&data_info[i], tmp+hd_idx, sizeof(struct sk_hd));	//copy header
		hd_idx += sizeof(struct sk_hd);

		data_info[i].send_queue = malloc(data_info[i].sk_hd.outq_len);  
		data_info[i].recv_queue = malloc(data_info[i].sk_hd.inq_len);

		memcpy(data_info[i].send_queue, tmp+len, data_info[i].sk_hd.outq_len);	//copy queue data
		len += data_info[i].sk_hd.outq_len;
		memcpy(data_info[i].recv_queue, tmp+len, data_info[i].sk_hd.inq_len);
		len += data_info[i].sk_hd.inq_len;

		//print_qdata(data_info[i]);
	}

}

dt_info* get_dump_info(int dt_connfd)
{
	int ret = 0;
	char recv_dt[800];
	char tmp[800];
	dt_info *data_info1;
	prefix pre1;
	pre1.conn_size = 0;
    
	ret = read(dt_connfd, recv_dt, 8000);
	printf("ret:%d\n", ret);

	memcpy(tmp, recv_dt, ret);
	memcpy(&pre1, tmp, sizeof(prefix));
	data_info1 = calloc(pre1.conn_size, sizeof(dt_info));
	get_data(data_info1, tmp, pre1);

	return data_info1;
}

void print_info(dt_info* data)
{
	char str[INET_ADDRSTRLEN];
		
	printf("final:\n");
	printf("data->inq_seq:%u\n", data->sk_hd.inq_seq);
	printf("data->outq_seq:%u\n", data->sk_hd.outq_seq);
	inet_ntop(AF_INET, &(data->sk_hd.src_addr), str, INET_ADDRSTRLEN);
	printf("src: %s:%u\n", str, data->sk_hd.src_port); 
	inet_ntop(AF_INET, &(data->sk_hd.dst_addr), str, INET_ADDRSTRLEN);
	printf("dst: %s:%u\n", str, data->sk_hd.dst_port); 
}
int dump_tcp_conn_state_HA(int fd, struct libsoccr_sk_data* data, prefix* hd, dt_info* buf)
{
    int ret;
    union libsoccr_addr sa_src, sa_dst;
	struct libsoccr_sk *socr = calloc(1, sizeof(struct libsoccr_sk));
    socr->fd = fd;
    
    
    set_addr_port(socr, &sa_src, &sa_dst);
    
    
	ret = libsoccr_save(socr, data, sizeof(*data));

	if (ret < 0) {
		printf("libsoccr_save() failed with %d\n", ret);
		return ret;
	}
	if (ret != sizeof(*data)) {
		printf("This libsocr is not supported (%d vs %d)\n",
				ret, (int)sizeof(*data));
		return ret;
	}
    
    save_sk_data(data, socr, buf);
    libsoccr_release(socr);
	return ret;
}
void dump_send(int sockfd, int proxy_dt_fd, struct libsoccr_sk_data* data, prefix* pre, dt_info* buf)
{
    int hd_idx, len;
    buf = calloc(pre->conn_size, sizeof(*buf));
    
    
    if (tcp_repair_on(sockfd) < 0) {
        printf("tcp_repair_on fail.\n");
        return;
    }
	else printf("tcp_repair successful.\n");
    

    for(int i = 0; i < pre->conn_size; i++)        // for loop to collect each socket data.
    {
		dump_tcp_conn_state_HA(sockfd, data, pre, &buf[i]);
    }
    
    hd_idx = sizeof(prefix);
    len = sizeof(prefix) + pre->conn_size*sizeof(struct sk_hd);
    char *send_data = malloc(len);

    memcpy(send_data, pre, sizeof(prefix));

    for(int i = 0; i < pre->conn_size; i++)        //for loop to store send out buf
    {
        send_data = realloc(send_data, len + buf[i].sk_hd.outq_len + buf[i].sk_hd.inq_len);
        final_save_data(send_data, &buf[i], hd_idx, len);
        len += buf[i].sk_hd.inq_len + buf[i].sk_hd.outq_len;
        hd_idx += sizeof(struct sk_hd);
    }
	
    if (tcp_repair_off(sockfd) < 0) {
        printf("tcp_repair_off fail.\n");
        return ;
    }
    
    write(proxy_dt_fd, send_data, len);
    free(send_data);
    free_buf(buf);  //need to decide when to free.
}

void save_sk_header(prefix* pre, uint16_t conn_size)
{
    pre->version = 1;
    pre->type = 1;
    pre->conn_size = conn_size;
}

int get_tcp_state(int sd)
{
    struct tcp_info t_info; /* the data structure of the TCP information */
    socklen_t t_info_len = sizeof(t_info); 

    if( getsockopt( sd, IPPROTO_TCP, TCP_INFO, &t_info, &t_info_len) != -1) {

        return t_info.tcpi_state; /* the state of the 'sd' TCP connection */
    }

    return -1;
}

void set_addr_port(struct libsoccr_sk *socr, union libsoccr_addr *sa_src, union libsoccr_addr *sa_dst)
{
	static int cnt = 0;
    struct sockaddr_in connectedAddr, peerAddr;
	int connectedAddrLen, peerLen;
	connectedAddrLen = sizeof(connectedAddr);  
	peerLen = sizeof(peerAddr);
	getsockname(socr->fd, (struct sockaddr *)&connectedAddr, &connectedAddrLen);
	getpeername(socr->fd, (struct sockaddr *)&peerAddr, &peerLen); 
	printf("connected server address = %s:%d\n", inet_ntoa(connectedAddr.sin_addr), ntohs(connectedAddr.sin_port));  
	printf("connected peer address = %s:%d\n", inet_ntoa(peerAddr.sin_addr), ntohs(peerAddr.sin_port));
	uint16_t src_port1 = ntohs(connectedAddr.sin_port);
	uint16_t dst_port1 = ntohs(peerAddr.sin_port);
	if((cnt++)%2 == 0)
	{
		uint16_t tmp_port = src_port1;
		src_port1 = dst_port1;
		dst_port1 = tmp_port;
		struct in_addr tmp_addr = connectedAddr.sin_addr;
		connectedAddr.sin_addr = peerAddr.sin_addr;
		peerAddr.sin_addr = tmp_addr;
	}

    bzero(sa_src, sizeof(*sa_src));
    bzero(sa_dst, sizeof(*sa_dst));
    
    
    if (restore_sockaddr_HA(sa_src,
				AF_INET, htons(src_port1),	
				&connectedAddr.sin_addr, 0) < 0)
		return;
	if (restore_sockaddr_HA(sa_dst,
				AF_INET, htons(dst_port1),	
				&peerAddr.sin_addr, 0) < 0)
		return;
    
	libsoccr_set_addr(socr, 1, sa_src, 0);
	libsoccr_set_addr(socr, 0, sa_dst, 0);
}

void print_qdata(dt_info data_info)
{
	char out_q[80], in_q[80];
	snprintf(out_q, data_info.sk_hd.outq_len+1, "%s", data_info.send_queue );
	snprintf(in_q, data_info.sk_hd.inq_len+1, "%s", data_info.recv_queue );
	printf("in_q:%s\t", in_q);
	printf("out_q:%s\n", out_q);
}

void save_sk_data(struct libsoccr_sk_data* data, struct libsoccr_sk* socr, dt_info* buf)
{
    buf->sk_hd.src_addr = socr->src_addr->v4.sin_addr.s_addr;
    buf->sk_hd.dst_addr = socr->dst_addr->v4.sin_addr.s_addr;
    buf->sk_hd.src_port = socr->src_addr->v4.sin_port;
    buf->sk_hd.dst_port = socr->dst_addr->v4.sin_port;
	
    memcpy(&buf->sk_hd.state, data, sizeof(*data));

    buf->send_queue = malloc(buf->sk_hd.outq_len);
    memcpy(buf->send_queue, socr->send_queue, data->outq_len);

    buf->recv_queue = malloc(buf->sk_hd.inq_len);
    memcpy(buf->recv_queue,socr->recv_queue,data->inq_len);
    
    print_qdata(*buf);
    
}

void final_save_data(char *send_data, dt_info *buf,int hd_idx, int q_idx)
{
    memcpy(send_data+hd_idx, &buf->sk_hd, sizeof(struct sk_hd));
    memcpy(send_data+q_idx, buf->send_queue, buf->sk_hd.outq_len);
    memcpy(send_data+q_idx+buf->sk_hd.outq_len, buf->recv_queue, buf->sk_hd.inq_len);
}


/*******************TCP repair by Howard****************/