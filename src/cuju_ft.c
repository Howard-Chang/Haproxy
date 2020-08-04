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
#include <common/libnet-structures.h>
#include <common/libnet-macros.h>
#include <pthread.h>
#include <sys/time.h>
#ifdef DEBUG_FULL
#include <assert.h>
#endif

#if ENABLE_CUJU_FT
#define FAKE_CUJU_ID 0

#if FAKE_CUJU_ID
u_int32_t guest_ip_db = 0xd47ea8c0;
#else

//u_int32_t guest_ip_db = 0xd47ea8c0;

/*
struct guest_ip_list
{
    u_int32_t guest_ip;
    struct list list;
};
*/
//static struct list pools = LIST_HEAD_INIT(pools);
static struct guest_ip_list gip_list = {
	.list = LIST_HEAD_INIT(gip_list.list)
};
#endif
int ft_mode = 1;
#define DEBUG_CUJU_IPC 0
#if DEBUG_CUJU_IPC
#define CJIRPRINTF(x...) printf(x)
#else
#define CJIRPRINTF(x...)
#endif

#define DEBUG_CUJU_IPC_ID 0
#if DEBUG_CUJU_IPC_ID
#define CJIDRPRINTF(x...) printf(x)
#else
#define CJIDRPRINTF(x...)
#endif

#define DEBUG_MSG 0
#if DEBUG_MSG
#define MSG_PRINTF(x...) printf(x)
#else
#define MSG_PRINTF(x...)
#endif

#define DEBUG_IPC 0
#if DEBUG_IPC
#define IPC_PRINTF(x...) printf(x)
#else
#define IPC_PRINTF(x...)
#endif

#define DEBUG_IPC_THREAD 0
#if DEBUG_IPC_THREAD
#define IPC_TH_PRINTF(x...) printf(x)
#else
#define IPC_TH_PRINTF(x...)
#endif

#define SUPPORT_VM_CNT 10
#define SAVE_SOCKET_STATE 1
u_int16_t fd_list_migration = 0;

static struct ft_fd_list ftfd_list = {
	.list = LIST_HEAD_INIT(ftfd_list.list)
};

u_int32_t fd_pipe_cnt = 0;
u_int16_t empty_pipe = 0;
u_int16_t empty_pbuffer = 0;
u_int16_t last_error = 0;

u_int16_t ipc_fd = 0;

struct gctl_ipc gctl_ipc;

int pb_event = 0;
int trace_cnt = 0;
int flush_cnt = 0;

/* NETLINK */
int nl_sock_fd = 0;
struct msghdr nl_msg;
struct netlink_ipc nl_ipc;
struct nlmsghdr *nlh = NULL;

#if ENABLE_TIME_MEASURE_EPOLL
struct timeval time_tepoll;
struct timeval time_tepoll_end;
unsigned long tepoll_time;
#endif

#if ENABLE_TIME_MEASURE
struct timeval time_poll;

struct timeval time_recv;
struct timeval time_recv_end;
unsigned long time_in_recv = 0;

struct timeval time_release;
struct timeval time_release_end;
unsigned long release_time = 0;

struct timeval time_loop;
struct timeval time_loop_end;
unsigned long loop_time = 0;

struct timeval time_send;
struct timeval time_send_end;
unsigned long time_in_send = 0;

struct timeval time_sicsp;
struct timeval time_sicsp_end;
unsigned long time_in_sicsp = 0;

struct timeval time_sicsio_send;
struct timeval time_sicsio_send_end;
unsigned long time_in_sicsio_send = 0;

struct timeval time_sicsio_recv;
struct timeval time_sicsio_recv_end;
unsigned long time_in_sicsio_recv = 0;

struct timeval time_sicsp_send;
struct timeval time_sicsp_send_end;
unsigned long time_in_sicsp_send = 0;

struct timeval time_sicsp_int;
struct timeval time_sicsp_int_end;
unsigned long time_in_sicsp_int = 0;
#endif

#if USING_SNAPSHOT_THREAD

#endif


#if FAKE_CUJU_ID
/* FAKE */
unsigned long flush_count = 1;
unsigned long epoch_count = 1;

unsigned long ft_get_flushcnt()
{
	return flush_count++;
}

unsigned long ft_get_epochcnt()
{
	return epoch_count++;
}
#else
/* FAKE */
//unsigned long flush_count = 0;
unsigned long ft_get_flushcnt()
{
	/* FAKE */
	//static unsigned long flush_count = 0;

	/* REAL */
	unsigned long flush_count = gctl_ipc.flush_id;

	return flush_count;
}

//unsigned long epoch_count = 0;
unsigned long ft_get_epochcnt()
{
	/* FAKE */
	//static unsigned long flush_count = 0;

	/* REAL */
	unsigned long epoch_count = gctl_ipc.epoch_id;

	return epoch_count;
}

#endif

#define MAX_SPLICE_AT_ONCE (1 << 30)

#define MAX_PAYLOAD 384
unsigned int total_ipc_idx = 1;
void *ipc_connection_handler(void *socket_desc);

#if 0
REGPRM1 static inline unsigned long tv_to_us(struct timeval *tv)
{
	unsigned long ret;

	ret  = tv->tv_sec * 1000 * 1000 + tv->tv_usec;

	return ret;
}
#else
/** Convert to micro-seconds */
__u64 tv_to_us(const struct timeval *tv)
{
	__u64 us = tv->tv_usec;
	us += (__u64)tv->tv_sec * (__u64)1000000;
	return us;
}
#endif

int ft_dup_pipe(struct pipe *source, struct pipe *dest, int clean)
{
	int ret = 0;
	static unsigned long retry_cnt = 0;

#if 1
	if (!source->data) {
#ifdef DEBUG_FULL
		printf("assert in %s source data is zero\n", __func__);
		assert(1);
#else
		return 0;
#endif
	}

	if (dest->data) {
#ifdef DEBUG_FULL
		printf("assert in %s dest data is not empty\n", __func__);
		assert(1);
#else
		return 0;
#endif
	}
#endif

	while (1) {
		if (clean == COPY_PIPE_CLEAN) {
			ret = splice(source->cons, NULL, dest->prod, NULL,
				     source->data, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
		} else {
			ret = tee(source->cons, dest->prod, source->data, SPLICE_F_NONBLOCK);
		}

		if (ret < 0) {
			if (errno == EAGAIN) {
				retry_cnt++;
				ret = 0;
				continue;
			}
			return ret;
		}
		break;
	}

	dest->data = source->data;
	dest->in_fd = source->in_fd;
	dest->out_fd = source->out_fd;

	if (source->epoch_idx) {
		dest->epoch_id = source->epoch_id;

		if (clean) {
			source->epoch_id = 0;
			source->epoch_idx = 0;
		}
	}

	if (source->flush_idx) {
		dest->flush_id = source->flush_id;

		if (clean) {
			source->flush_id = 0;
			source->flush_idx = 0;
		}
	}

	return ret;
}

int ft_close_pipe(struct pipe *pipe, int *pipe_cnt)
{
	int ret = 0;
	struct pipe *pipe_trace = pipe;
	struct pipe *pipe_prev = NULL;

	if (pipe->pipe_nxt) {
		/* search pipe_next is empty insert new incoming to the pipe buffer tail */
		while (1) {
			if (pipe_trace == NULL) {
				break;
			}

			if (pipe_trace->pipe_nxt == NULL) {
				break;
			}

			pipe_prev = pipe_trace;
			pipe_trace = pipe_trace->pipe_nxt;

			pipe_prev->pipe_nxt = pipe_trace->pipe_nxt;

			ft_clean_pipe(pipe_trace->pipe_dup);
			put_pipe(pipe_trace->pipe_dup);

			ft_clean_pipe(pipe_trace);
			put_pipe(pipe_trace);
			(*pipe_cnt) -= 2;
			printf("release pipe 2 total:%d\n", (*pipe_cnt));

			pipe_trace = pipe_prev->pipe_nxt;
		}
	}
	return ret;
}

int ft_release_pipe_by_flush(struct pipe *pipe, uint32_t flush_id,
			     uint16_t *total_pipe_cnt, uint16_t *pipe_cnt)
{
	int ret = 0;
	struct pipe *pipe_trace = pipe;
	struct pipe *pipe_prev = NULL;

	//printf("%s  %d\n", __func__, *total_pipe_cnt);

	if (pipe->pipe_nxt) {

		/* search next is empty insert new incoming to the pipe buffer tail */
		while (1) {
			if (pipe_trace == NULL) {
				//printf("pipe_trace NULL\n");
				break;
			}

			if (pipe_trace->pipe_nxt == NULL) {
				//printf("pipe_trace->pipe_nxt NULL\n");
				break;
			}

			//printf("pipe_trace: %p\n", pipe_trace);

			pipe_prev = pipe_trace;
			pipe_trace = pipe_trace->pipe_nxt;

			//printf("Current pipe_trace: %p\n", pipe_trace);

			/* TODO: consider overflow */
			if (pipe_trace->flush_id < flush_id) {
				//printf("pipe_trace->transfered: %p %p\n", pipe_trace->pipe_dup, pipe_trace);

				pipe_prev->pipe_nxt = pipe_trace->pipe_nxt;

				if (pipe_trace->pipe_dup) {
					ft_clean_pipe(pipe_trace->pipe_dup);
					put_pipe(pipe_trace->pipe_dup);
				}

				ft_clean_pipe(pipe_trace);
				put_pipe(pipe_trace);

				(*pipe_cnt) -= 2;
				(*total_pipe_cnt) -= 2;

				printf("release pipe 2 total:%d\n", (*total_pipe_cnt));

				pipe_trace = pipe_prev->pipe_nxt;
			}
		}
	}

	return ret;
}

int ft_release_pipe_by_transfer(struct pipe *pipe, uint16_t *total_pipe_cnt,
				uint16_t *pipe_cnt)
{
	int ret = 0;
	struct pipe *pipe_trace = pipe;
	struct pipe *pipe_prev = NULL;

	int trace_cnt = 0;
	int transfer_cnt = 0;

	//printf("%s  %d\n", __func__, *total_pipe_cnt);

	if (pipe->pipe_nxt) {
		/* search pipe_nxt is empty insert new incoming to the pipe buffer tail */
		while (1) {
			if (pipe_trace == NULL) {
				//printf("pipe_trace NULL\n");
				break;
			}

			if (pipe_trace->pipe_nxt == NULL) {
				//printf("pipe_trace->pipe_nxt NULL\n");
				break;
			}

			//printf("pipe_trace: %p\n", pipe_trace);

			pipe_prev = pipe_trace;
			pipe_trace = pipe_trace->pipe_nxt;

			//printf("Current pipe_trace: %p\n", pipe_trace);

			trace_cnt++;

			/* TODO: consider overflow */
			if (pipe_trace->transfered) {
				pipe_prev->pipe_nxt = pipe_trace->pipe_nxt;

				//printf("pipe_trace->transfered: %p %p\n", pipe_trace->pipe_dup, pipe_trace);
				//printf("pipe_trace->transfered: %p\n", pipe_trace);

				//ft_clean_pipe(pipe_trace->pipe_dup);
				//put_pipe(pipe_trace->pipe_dup);

				ft_clean_pipe(pipe_trace);
				put_pipe(pipe_trace);

				printf("release pipe 1 total:%d\n", (*total_pipe_cnt));

				transfer_cnt++;
				(*pipe_cnt)--;
				(*total_pipe_cnt)--;

				pipe_trace = pipe_prev->pipe_nxt;
			} else {
				printf("Transfered End\n");
				break;
			}
		}
	}
	//printf("===================================\n");
	//printf ("Flush trace count:%d ted:%d\n", trace_cnt, transfer_cnt);

	return ret;
}

void ft_clean_pipe(struct pipe *pipe)
{
	if (pipe) {
		pipe->pipe_dup = NULL;
		pipe->flush_id = 0;
		pipe->flush_idx = 0;
		pipe->epoch_id = 0;
		pipe->epoch_idx = 0;
		pipe->in_fd = 0;
		pipe->out_fd = 0;
		pipe->trans_suspend = 0;
		pipe->transfer_cnt = 0;
		pipe->transfered = 0;
		pipe->pipe_nxt = NULL;

		put_pipe(pipe);
	}
}

int cuju_process(struct conn_stream *cs)
{
	struct connection *conn = cs->conn;
	struct stream_interface *si = cs->data;
	struct channel *ic = si_ic(si);
	//struct channel *oc = si_oc(si);
	//unsigned int idx = 0;
	struct proto_ipc *ipc_ptr = NULL;
	u_int32_t dynamic_ipc = 0;
	u_int8_t *dynamic_array = NULL;
	u_int32_t guest_ip_db = 0;
	struct guest_ip_list *guest_info = NULL;

	CJIDRPRINTF("%s data:%zu\n", __func__, ic->buf.data);

	/* area may be zero */
	*(((char *)ic->buf.area) + ic->buf.data) = '\0';

	if (!ic->buf.data) {
		return -1;
	}

	ipc_ptr = (struct proto_ipc *)ic->buf.area;

	if ((ipc_ptr->nic_count <= DEFAULT_NIC_CNT) &&
	    (ipc_ptr->conn_count <= DEFAULT_CONN_CNT)) {

#if 0
		if (ic->buf.data != DEFAULT_IPC_ARRAY) {
			printf("Unexpected IPC Data\n");
			assert(0);
		}
#endif

		dynamic_ipc = (IP_LENGTH * ipc_ptr->nic_count) + (CONNECTION_LENGTH *
				ipc_ptr->conn_count);
		dynamic_array = (u_int8_t *)ic->buf.area + sizeof(struct proto_ipc);
	} else {
		if (ic->buf.data != sizeof(struct proto_ipc) + dynamic_ipc) {
			printf("Unexpected IPC Data Not Default Value\n");
			assert(0);
		}
	}
	printf("cuju_process @@@@@@@@@@@@@@@@@@@@\n");
	//if ((ipc_ptr->cuju_ft_mode == CUJU_FT_INIT) || (ipc_ptr->cuju_ft_arp)) {
	if (ipc_ptr->cuju_ft_mode == CUJU_FT_INIT) {
		//printf ("VM NIC CNT: %d\n", ipc_ptr->nic_count);

		ipc_fd = conn->handle.fd;

		printf("[%s]FD:%d!!!!!\n", __func__, ipc_fd);

		if (ipc_ptr->nic_count) {
			for (int idx = 0; idx < ipc_ptr->nic_count; idx++) {
				guest_ip_db = ntohl(*(((u_int32_t *)dynamic_array) + idx));

				printf("Find IP String %08x\n", guest_ip_db);

				if (ipc_ptr->cuju_ft_mode == CUJU_FT_INIT) {
					if (guest_info) {
						/* add 2nd ip to original */
					} else {
						guest_info = add_guestip(guest_ip_db);
						if (!guest_info)
							assert(1);
					}
				}
			}
		}
	}

	if (ipc_ptr->cuju_ft_mode != CUJU_FT_INIT) {
		guest_ip_db = ntohl(*((u_int32_t *)dynamic_array));
		guest_info = find_guestip_ptr(guest_ip_db);
		if (!guest_info)
			assert(1);
	}

	/* Set GCTL */
	printf("Cuju FT mode Check\n");
	if (ipc_ptr->cuju_ft_mode == CUJU_FT_TRANSACTION_RUN) {
		guest_info->gctl_ipc.epoch_id = ipc_ptr->epoch_id;
		CJIDRPRINTF("[%s] Epoch ID:%u\n", __func__, ipc_ptr->epoch_id);
	} else if (ipc_ptr->cuju_ft_mode == CUJU_FT_TRANSACTION_FLUSH_OUTPUT) {
		guest_info->gctl_ipc.flush_id = ipc_ptr->epoch_id;
		CJIDRPRINTF("[%s] Flush ID:%u\n", __func__, ipc_ptr->epoch_id);
	} else if (ipc_ptr->cuju_ft_mode == CUJU_FT_TRANSACTION_HANDOVER) {
		printf("[%s] Failover:%u\n", __func__, ipc_ptr->epoch_id);
		CJIDRPRINTF("[%s] Failover:%u\n", __func__, ipc_ptr->epoch_id);
	}

	//printf("cuju_ft_mode is %d\n", ipc_ptr->cuju_ft_mode);

	/* clear */
	ic->buf.data = 0;

	if (cs->conn->cujuipc_idx) {
		cs->conn->flags &= ~CO_FL_CURR_RD_ENA;

		conn_update_xprt_polling(conn);

		fd_cant_recv(conn->handle.fd);
	}

	return 0;
}

char *arp_get_ip(const char *req_mac)
{
	FILE *proc;
	char ip[16];
	char mac[18];
	char *reply = NULL;

	if (!(proc = fopen("/proc/net/arp", "r"))) {
		return NULL;
	}

	/* Skip first line */
	while (!feof(proc) && fgetc(proc) != '\n')
		;

	/* Find ip, copy mac in reply */
	reply = NULL;
	while (!feof(proc) &&
	       (fscanf(proc, " %15[0-9.] %*s %*s %17[A-Fa-f0-9:] %*s %*s", ip, mac) == 2)) {
		if (strcmp(mac, req_mac) == 0) {
			//reply = safe_strdup(ip);
			reply = strdup(ip);
			break;
		}
	}

	fclose(proc);

	return reply;
}

REGPRM1 static inline unsigned long tv_to_us_show(struct timeval *tv)
{
	printf("S: %lx\n", tv->tv_sec);
	printf("U: %lx\n", tv->tv_usec);
	return 0;
}

unsigned long max_send_time = 0;
unsigned long max_recv_time = 0;

void show_ft_time(void)
{
#if ENABLE_TIME_MEASURE
	unsigned long send_time = 0;
	unsigned long recv_time = 0;
#endif
#if 0
	printf("\n");
	printf("%lx   %lx    %lx    %lx    %lx\n",
	       tv_to_us(&time_poll), tv_to_us(&time_recv), tv_to_us(&time_recv_end),
	       tv_to_us(&time_send), tv_to_us(&time_send_end));
#endif
#if 1

#if 0
	printf("*******************************\n");
	tv_to_us_show(&time_poll);
	tv_to_us_show(&time_recv);
	tv_to_us_show(&time_recv_end);
	tv_to_us_show(&time_send);
	tv_to_us_show(&time_send_end);
	printf("***************END*************\n");
#endif
#if ENABLE_TIME_MEASURE
	send_time = tv_to_us(&time_send_end) - tv_to_us(&time_send);
	recv_time = tv_to_us(&time_recv_end) - tv_to_us(&time_recv);

	if (recv_time > max_recv_time) {
		max_recv_time = recv_time;
	}

	if (send_time > max_send_time) {
		max_send_time = send_time;
	}

	printf("%lu %lu %lu %lu\n\n", recv_time, send_time, max_recv_time, max_send_time);
#endif
#endif
#if 0
	if (pb_event) {
		printf("%lu %lu\n\n",
		       tv_to_us(&time_send) - tv_to_us(&time_poll),
		       tv_to_us(&time_send_end) - tv_to_us(&time_send));
	} else {
		printf("%lu    %lu    %lu    %lu\n\n",
		       tv_to_us(&time_recv) - tv_to_us(&time_poll),
		       tv_to_us(&time_recv_end) - tv_to_us(&time_recv),
		       tv_to_us(&time_send) - tv_to_us(&time_recv_end),
		       tv_to_us(&time_send_end) - tv_to_us(&time_send));
	}
#endif
}

struct guest_ip_list *find_guestip_ptr(u_int32_t guest_ip)
{

	struct guest_ip_list *gipl;

	list_for_each_entry(gipl, &gip_list.list, list) {
		if (gipl->guest_ip == guest_ip) {
			return gipl;
		}
	}
	return NULL;
}

u_int8_t find_guestip_exist(u_int32_t guest_ip)
{

	struct guest_ip_list *gipl;

	list_for_each_entry(gipl, &gip_list.list, list) {
		if (gipl->guest_ip == guest_ip) {
			return 1;
		}
	}
	return 0;
}

struct guest_ip_list *add_guestip(u_int32_t guest_ip)
{
	struct guest_ip_list *gipl;

	/* allocate list */
	gipl = calloc(1, sizeof(*gipl));
	if (!gipl) {
		printf("out of memory while indexing pattern\n");
		return NULL;
	}

	gipl->guest_ip = guest_ip;

	LIST_ADDQ(&gip_list.list, &gipl->list);

	return gipl;
}

u_int8_t del_guestip(u_int32_t guest_ip)
{
	struct guest_ip_list *gipl;

	list_for_each_entry(gipl, &gip_list.list, list) {
		if (gipl->guest_ip == guest_ip) {
			LIST_DEL(&gipl->list);
			free(gipl);
			return 1;
		}
	}
	return 0;
}

struct guest_ip_list *check_guestip(u_int32_t source, u_int32_t dest, uint8_t *dir)
{
	struct guest_ip_list *gipl;

	list_for_each_entry(gipl, &gip_list.list, list) {
		if (gipl->guest_ip == source) {
			*dir = DIR_DEST_CLIENT;
			return gipl;
		}

		if (gipl->guest_ip == dest) {
			*dir = DIR_DEST_GUEST;
			return gipl;
		}
	}

	printf("Miss guest IP\n");
	return NULL;
}

u_int16_t get_ft_fd(void)
{
	u_int16_t tmp_fd = 0;
	struct ft_fd_list *ftfdl;
	struct ft_fd_list *def;

	list_for_each_entry_safe(ftfdl, def, &ftfd_list.list, list) {
		if (ftfdl->ft_fd != 0) {
			tmp_fd = ftfdl->ft_fd;
			/* release */
			ftfdl->ft_fd = 0;
			LIST_DEL(&ftfdl->list);
			free(ftfdl);
			return tmp_fd;
		}
	}

	return 0;
}

u_int8_t add_ft_fd(u_int16_t ftfd)
{
	struct ft_fd_list *ftfdl;

	/* allocate list */
	ftfdl = calloc(1, sizeof(*ftfdl));
	if (!ftfdl) {
		printf("out of memory while indexing pattern\n");
		return 0;
	}

	ftfdl->ft_fd = ftfd;

	LIST_ADDQ(&ftfd_list.list, &ftfdl->list);

	return 1;
}

uint16_t getshmid(u_int32_t source, u_int32_t dest, uint8_t *dir)
{
	struct proto_ipc *ptr = ipt_target;
	unsigned int idx = 0;

	printf("[%s] ipt_target:%p  source:%08x dest:%08x\n", __func__, ipt_target, source, dest);
	printf("[%s] base:%p base+1:%p\n", __func__, ptr, (ptr + 1));
	//if (ipt_target->nic_count) {
	for (idx = 0; idx < SUPPORT_VM_CNT; idx++) {
		printf("IDX:%d IP:%08x\n", idx, (ptr + idx)->nic[0]);

		if ((source != 0) && ((ptr + idx)->nic[0] == source)) {
			printf("[%s] DIR_DEST_CLIENT\n", __func__);
			*dir = DIR_DEST_CLIENT;
			return idx;
		}
		if ((dest != 0) && ((ptr + idx)->nic[0] == dest)) {
			printf("[%s] DIR_DEST_GUEST\n", __func__);
			*dir = DIR_DEST_GUEST;
			return idx;
		}

#if 0
		if (*(u_int32_t *)((struct proto_ipc *)(ipt_target + idx)->nic[1]) == source) {
			*dir = DIR_DEST_CLIENT;;
			return idx;
		}

		if (*(u_int32_t *)((struct proto_ipc *)(ipt_target + idx)->nic[1]) == dest) {
			*dir = DIR_DEST_GUEST;;
			return idx;
		}
#endif
	}
	//}
	return 0;
}
#endif

struct vm_list vm_head = {
	.vm_list = LIST_HEAD_INIT(vm_head.vm_list)
	//.skid_head = LIST_HEAD_INIT(vm_head.skid_head)
};

struct vm_list *vm_in_table(struct list *table, u_int32_t vm_ip)
{
	/* search and insert */
	struct vm_list *target;

	list_for_each_entry(target, table, vm_list) {
		if (target->vm_ip == vm_ip) {
			return target;
		}
	}

	return NULL;
}

int add_vmlist_by_conn(struct connection* conn, int cli_srv)
{
    int direction = DIR_NO_CHECK;
    if (conn == NULL)
        return;
	printf("add_vmlist_by_conn ##############################\n");
    conn->addr_from = ntohl(((struct sockaddr_in *)&conn->addr.from)->sin_addr.s_addr);
    conn->addr_to = ntohl(((struct sockaddr_in *)&conn->addr.to)->sin_addr.s_addr);
    getshmid(conn->addr_from, conn->addr_to, &direction);
    if ((direction == DIR_DEST_GUEST) && (cli_srv == CONN_IS_SERVER)) {
        printf("[%s] DIR_DEST_GUEST %d\n", __func__, conn->handle.fd);
        add_vm_target(&vm_head.vm_list, ntohl(((struct sockaddr_in *)&conn->addr.to)->sin_addr.s_addr), conn->handle.fd, conn);
        conn->direction = direction;
    }
    if ((direction == DIR_DEST_CLIENT) && (cli_srv == CONN_IS_CLIENT)) {
        printf("[%s] DIR_DEST_CLIENT %d\n", __func__, conn->handle.fd);
        add_vm_target(&vm_head.vm_list, ntohl(((struct sockaddr_in *)&conn->addr.from)->sin_addr.s_addr), conn->handle.fd, conn);
        conn->direction = direction;
    }
    return 0;
}

struct vm_list *add_vm_target(struct list *table, u_int32_t vm_ip, u_int32_t socket_id,
			      struct connection *conn)
{
	struct vm_list *target = NULL;
	struct vmsk_list *target_sk = NULL;
	//u_int32_t vm_ip = ntohl(vmip);

	if (LIST_ISEMPTY(table)) {
#if 0
		struct vm_list *new_vm = NULL;
		struct vmsk_list *new_sk = NULL;

		new_vm = (struct vm_list *)malloc(sizeof(struct vm_list));

		if (new_vm == NULL) {
			return NULL;
		}

		new_vm->vm_ip = vm_ip;

		if (socket_id) {
			new_sk = (struct vmsk_list *)malloc(sizeof(struct vmsk_list));

			if (new_sk == NULL) {
				free(new_vm);
				return NULL;
			}

			new_sk->socket_id = socket_id;
			new_vm->skid_head.skid_list.n = &new_vm->skid_head.skid_list;
			new_vm->skid_head.skid_list.p = &new_vm->skid_head.skid_list;
			//new_vm->skid_head.skid_list = LIST_HEAD_INIT(&new_vm->skid_head.skid_list);

			//new_vm->ss_data.locker = PTHREAD_MUTEX_INITIALIZER;
			//new_vm->ss_data.cond = PTHREAD_COND_INITIALIZER;

			LIST_ADDQ(&new_vm->skid_head.skid_list, &new_sk->skid_list);
		}
		//LIST_HEAD_INIT(&new_vm->skid_head);
		//list_add_tail(&new_sk->skid_list, &new_vm->skid_head);
		//list_add_tail(&new_vm->vm_list, table);

		LIST_ADDQ(&vm_head.vm_list, &new_vm->vm_list);

		return new_vm;
#else
		goto create_newvm;
#endif
	} else {
		/* search and insert */

		list_for_each_entry(target, table, vm_list) {
			if (target->vm_ip == vm_ip) {
				/* insert new port to target IP */
				if (socket_id) {
					pthread_mutex_lock(&(target->socket_metux));	

					list_for_each_entry(target_sk, &target->skid_head.skid_list, skid_list) {
						if (target_sk->socket_id == socket_id) {
							/* already exist */
							return target;
						}
					}

					target_sk = (struct vmsk_list *)malloc(sizeof(struct vmsk_list));

					if (target_sk == NULL) {
						return NULL;
					}
					target_sk->socket_id = socket_id;
					target->socket_count++;
					target_sk->conn = conn;

					LIST_ADDQ(&target->skid_head.skid_list, &target_sk->skid_list);
					pthread_mutex_unlock(&(target->socket_metux));	
				}
				return target;
			}
		}

create_newvm:

		target = (struct vm_list *)malloc(sizeof(struct vm_list));

		if (target == NULL) {
			return NULL;
		}
		target->vm_ip = vm_ip;
		printf("[%s] new vm %p and ip %08x\n", __func__, target, vm_ip);

		pthread_mutex_init(&(target->socket_metux), NULL);

		if (socket_id) {
			pthread_mutex_lock(&(target->socket_metux));

			target_sk = (struct vmsk_list *)malloc(sizeof(struct vmsk_list));

			if (target_sk == NULL) {
				free(target);
				return NULL;
			}

			target_sk->socket_id = socket_id;
			target_sk->conn = conn;
			target->socket_count++;
			target->skid_head.skid_list.n = &target->skid_head.skid_list;
			target->skid_head.skid_list.p = &target->skid_head.skid_list;
			//target->skid_head.skid_list = LIST_HEAD_INIT(&new_vm->skid_head.skid_list);
			LIST_ADDQ(&target->skid_head.skid_list, &target_sk->skid_list);
		} else {
			target->skid_head.skid_list.n = &target->skid_head.skid_list;
			target->skid_head.skid_list.p = &target->skid_head.skid_list;
		}

		LIST_ADDQ(&vm_head.vm_list, &target->vm_list);

		return target;
	}

	/* Can't find the target IP */
	return NULL;
}

int del_target(struct list *table, u_int32_t vm_ip, u_int32_t socket_id)
{
	/* search and insert */
	struct vm_list *target = NULL;
	struct vm_list *t_temp = NULL;
	struct vmsk_list *target_sk = NULL;
	struct vmsk_list *sk_temp = NULL;

	list_for_each_entry_safe(target, t_temp, table, vm_list) {
		printf("\t\tFind IP in delete:%08x\n", target->vm_ip);

		if (target->vm_ip == vm_ip) {
			list_for_each_entry_safe(target_sk, sk_temp, &target->skid_head.skid_list, skid_list) {
				if (target_sk->socket_id == socket_id) {
					printf("\t\tRemove SK:%08x\n", target_sk->socket_id);
					pthread_mutex_lock(&(target->socket_metux));	

					target->socket_count--;
					LIST_DEL(&target_sk->skid_list);

					free(target_sk);

					pthread_mutex_unlock(&(target->socket_metux));	
				}
			}

			if (!target->fault_enable) {
				if (LIST_ISEMPTY(&target->skid_head.skid_list)) {
					LIST_DEL(&target->vm_list);
					free(target);
				}
			}
			break;
		}
	}

	return 0;
}

int show_target_rule(struct list *table)
{
	struct vm_list *target;
	struct vmsk_list *target_sk;

	printf("========================= START =========================\n");

	list_for_each_entry(target, table, vm_list) {
		printf("IP:%08x  Count:%d\n", target->vm_ip, target->socket_count);
		if (target->socket_count) {
			list_for_each_entry(target_sk, &target->skid_head.skid_list, skid_list) {
				printf("\tSocket ID:%08x\n", target_sk->socket_id);
			}
		}
	}
	printf("========================= END =========================\n");

	return 0;
}

int clean_target_list(struct list *table)
{
	struct vm_list *target = NULL;
	struct vm_list *t_temp = NULL;
	struct vmsk_list *target_sk = NULL;
	struct vmsk_list *sk_temp = NULL;

	list_for_each_entry_safe(target, t_temp, table, vm_list) {
		printf("\t\tFind IP in clean list:%08x\n", target->vm_ip);

		if (target != NULL) {

			list_for_each_entry_safe(target_sk, sk_temp, &target->skid_head.skid_list, skid_list) {
				if (target_sk != NULL) {
					printf("\t\tRemove socket ID in clean list:%08x\n", target_sk->socket_id);
					LIST_DEL(&target_sk->skid_list);
					free(target_sk);
				}
			}

			if (LIST_ISEMPTY(&target->skid_head.skid_list)) {
				LIST_DEL(&target->vm_list);
				free(target);
			}
		}
	}

	return 0;
}

/**
 * #################################################### ipc_handler ####################################################
 */

#if 1

struct fo_list fo_head = {
	.fo_list = LIST_HEAD_INIT(fo_head.fo_list)
};

struct fo_list *pop_failover(unsigned int nic)
{
	struct fo_list *target = NULL;
	struct fo_list *out_temp = NULL;

	IPC_PRINTF("Pop target:%08x\n", nic);

	list_for_each_entry_safe(target, out_temp, &fo_head.fo_list, fo_list) {
		IPC_PRINTF("List target: %08x\n", target->nic);
		if (target->nic == nic) {
			IPC_PRINTF("\tRemove failover list\n");
			LIST_DEL(&target->fo_list);
			return target;
		}
	}
	return NULL;
}

void *ipc_handler(void)
{
	int shm_id = 0;

	//socket的建立

	int sockfd = 0;
	int forClientSockfd = 0;
	struct sockaddr_in serverInfo;
	struct sockaddr_in clientInfo;
	int addrlen = sizeof(clientInfo);
	pthread_t thread_id;
	struct thread_data thread_data;

#if USING_NETLINK
	int netlink_sock_fd = 0;
	struct sockaddr_nl src_addr;
#endif

	IPC_PRINTF("Start\n\n");

	/* get the ID of shared memory */
	shm_id = shmget((key_t)KEY_SHM_CUJU_IPC, SUPPORT_VM_CNT * (sizeof(struct proto_ipc)),
			0666 | IPC_CREAT);

	if (shm_id == -1) {
		perror("shmget error\n");
		exit(EXIT_FAILURE);
	}

	/* attach shared memory */
	ipt_target = (struct proto_ipc *)shmat(shm_id, (void *)0, 0);
	if (ipt_target == (void *) - 1) {
		perror("shmget error");
		exit(EXIT_FAILURE);
	}

	IPC_PRINTF("Shared Memory Ok\n");

	memset(ipt_target, 0x00, SUPPORT_VM_CNT * (sizeof(struct proto_ipc)));

	IPC_PRINTF("share memory start:%p total max:%lu\n", ipt_target,
		   SUPPORT_VM_CNT * (sizeof(struct proto_ipc)));

#if USING_NETLINK
	netlink_sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
	if (netlink_sock_fd <= 0) {
		perror("create socket failed!\n");
		return -1;
	}

	printf("Netlink Socket ID:%d\n", netlink_sock_fd);

	memset(&src_addr, 0, sizeof(struct sockaddr_nl));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	src_addr.nl_groups = 0;

	if (bind(netlink_sock_fd, (struct sockaddr *)&src_addr, sizeof(struct sockaddr)) < 0) {
		perror("bind socket failed!\n");
		close(netlink_sock_fd);
		return -1;
	}
#endif

#if 0 //DEBUG_SHM
	while (1) {
		ipt_target->epoch_id++;
		usleep(5000);
	}
#else
	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sockfd == -1) {
		perror("Fail to create a socket.\n");
	}

	//socket的連線
	bzero(&serverInfo, sizeof(serverInfo));

	serverInfo.sin_family = PF_INET;
	serverInfo.sin_addr.s_addr = INADDR_ANY;
	serverInfo.sin_port = htons(1200);

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (const char*)&one, sizeof(one)) < 0) 
		perror("setsockopt(SO_REUSEPORT) failed");

	bind(sockfd, (struct sockaddr *)&serverInfo, sizeof(serverInfo));

	listen(sockfd, 5);

	IPC_PRINTF("Wait accepted\n");

	while ((forClientSockfd = accept(sockfd, (struct sockaddr *)&clientInfo,
					 (socklen_t *)&addrlen)) > 0) {
		IPC_PRINTF("Connection accepted:%d\n", forClientSockfd);

		thread_data.th_idx = total_ipc_idx++;
		thread_data.th_sock = forClientSockfd;
#if 0
		if (list_empty(&failover_list)) {
			printf("list is empty\n");
			thread_data.th_sock = forClientSockfd;
		} else {
			printf("list is not empty\n");
			thread_data.th_sock = 0;
		}
#endif
		thread_data.ipt_base = ipt_target;
		////thread_data.netlink_sock = netlink_sock_fd;
		printf("Thread IPT base address %p\n", ipt_target);

		if (pthread_create(&thread_id, NULL, ipc_connection_handler, (void *)&thread_data) < 0) {
			perror("could not create thread");
			goto func_error;
		}

		////////
		//pthread_join(thread_id, NULL);

		//Now join the thread , so that we dont terminate before the thread
		//pthread_join( thread_id , NULL);
		IPC_PRINTF("Handler assigned\n");
		printf("Handler assigned\n");
	}

	IPC_PRINTF("Close\n");
#endif

	/* detach shared memory */
	if (shmdt(ipt_target) == -1) {
		perror("shmdt");
		goto func_error;
	}

	/* destroy shared memory */
	if (shmctl(shm_id, IPC_RMID, 0) == -1) {
		perror("shmctl");
		goto func_error;
	}
func_error:

	printf("[%s] Close Thread\n", __func__);
	pthread_exit(NULL);
	//return NULL; 
}
/*
 * This will handle connection for each client
 * */
void *ipc_connection_handler(void *socket_desc)
{
	//Get the socket descriptor
	int sock = ((struct thread_data *)socket_desc)->th_sock;
	int shm_idx = ((struct thread_data *)socket_desc)->th_idx;
	int primary_shm_idx = 0;
	struct proto_ipc *ipt_addr = NULL;
	//struct proto_ipc * ipt_addr = ((struct thread_data*)socket_desc)->ipt_base + shm_idx;

	int read_size = 0;
	unsigned char client_message[sizeof(struct proto_ipc)];
	struct proto_ipc *ipc_ptr = NULL;
	//u_int32_t guest_ip_db = 0;
	unsigned int base_nic = 0x0;
	struct fo_list *fo_temp = NULL;
	struct vm_list *target_vm = NULL;
	pthread_t thread_snapshot;

#if USING_NETLINK
	int sock_fd = ((struct thread_data *)socket_desc)->netlink_sock;
	struct sockaddr_nl dest_addr;
	struct nlmsghdr *nlh = NULL;
	struct iovec iov;
	struct msghdr msg;
	struct netlink_ipc nl_ipc;

	memset(&dest_addr, 0, sizeof(struct sockaddr_nl));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0;
	dest_addr.nl_groups = 0;

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	if (nlh == NULL) {
		perror("malloc nlmsghdr failed!\n");
		close(sock_fd);
		return 0;
	}
	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;

	iov.iov_base = (void *)nlh;
	iov.iov_len = NLMSG_SPACE(MAX_PAYLOAD);

	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(struct sockaddr_nl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	MSG_PRINTF("[%s]\n", __func__);
#endif
	//if (shm_idx != 0) {
	//    ipt_addr = ((struct thread_data*)socket_desc)->ipt_base + shm_idx;
	//}

	while (read_size = recv(sock, client_message, 2000, 0)) {
		//end of string marker
		//client_message[read_size] = '\0';
		//printf("Size:%d\n", read_size);

#if 0  //DEBUG_IPC
		printf("Size:%d\n", read_size);

		for (int idx = 0; idx < read_size; idx++) {
			printf("%02x ", *(client_message + idx));

			if (idx % 8 == 7)
				printf("\n");
		}
		printf("\n");
#endif
		ipc_ptr = (struct proto_ipc *)client_message;

		//printf("NIC: %08x\n", ipc_ptr->nic[0]);

		IPC_PRINTF("shm_idx:%d p_shm_idx:%d True:%d\n", shm_idx, primary_shm_idx,
			   !LIST_ISEMPTY(&fo_head.fo_list));

		//if (shm_idx == 0 && primary_shm_idx == 0 && !list_empty(&failover_list)) {

		base_nic = ipc_ptr->nic[0];

		/* this may occur after CUJU_FT_TRANSACTION_SNAPSHOT */

		IPC_PRINTF("[%s] POP_FAILOVER %08x\n", __func__, ipc_ptr->nic[0]);
		fo_temp = pop_failover((ipc_ptr->nic[0]));

		if (fo_temp != NULL) {
			IPC_PRINTF("failover list not empty\n");
			printf("failover list not empty\n");
			primary_shm_idx = fo_temp->socket_id;
			ipt_addr = ((struct thread_data *)socket_desc)->ipt_base + primary_shm_idx;
			free(fo_temp);

			target_vm = vm_in_table(&vm_head.vm_list, base_nic);
			if (!target_vm) {
				printf("ERROR\n");
				assert(0);
			}

			target_vm->failovered = 1;
			IPC_PRINTF("[FT_FAILOVER] vm_data: %p\n", target_vm);

			pthread_cond_signal(&target_vm->ss_data.cond);

		} else {
			IPC_PRINTF("failover list is empty!!!\n");
			////printf("failover list is empty!!!\n");
			ipt_addr = ((struct thread_data *)socket_desc)->ipt_base + shm_idx;
			////printf("ipt_addr %p IDX:%d\n", ipt_addr, shm_idx);
		}

		//MSG_PRINTF("ipt_addr:%p  ipc_ptr:%p\n", ipt_addr, ipc_ptr);

		ipt_addr->epoch_id = ipc_ptr->epoch_id;
		ipt_addr->flush_id = ipc_ptr->flush_id;
		ipt_addr->nic_count = ipc_ptr->nic_count;
		ipt_addr->nic[0] = ipc_ptr->nic[0];
		ipt_addr->cuju_ft_mode = ipc_ptr->cuju_ft_mode;

		IPC_PRINTF("FT mode:%d\n", ipc_ptr->cuju_ft_mode);
		IPC_PRINTF("E/F ID:%d\n", ipc_ptr->epoch_id);
		IPC_PRINTF("NICCount:%d\n", ipc_ptr->nic_count);


		//printf("NIC IP1:%08x\n", ipt_addr->nic[0]);

		if (ipc_ptr->epoch_id != ipc_ptr->flush_id) {
			IPC_PRINTF("Match\n");
		}

		if (ipc_ptr->cuju_ft_mode == CUJU_FT_TRANSACTION_SNAPSHOT) {
			IPC_PRINTF("FT mode is CUJU_FT_TRANSACTION_SNAPSHOT\n");
			//printf("FT mode is SNAPSHOT from %08x\n", ipc_ptr->nic[0]);
			//pthread_cond_signal();

			target_vm = vm_in_table(&vm_head.vm_list, base_nic);
			if (!target_vm) {
				printf("target_vm is NULL\n");
				assert(0);
			}

			target_vm->nic[1]++;
			IPC_PRINTF("[FT_SNAPSHOT]vm_data: %p\n", target_vm);

			pthread_cond_signal(&target_vm->ss_data.cond);
			IPC_PRINTF("CUJU_FT_TRANSACTION_SNAPSHOT End\n");
		}

#if USING_SNAPSHOT_THREAD
		if (ipc_ptr->cuju_ft_mode == CUJU_FT_INIT) {

			
			struct vm_list *vm_data = NULL;
			ft_mode = 1;
			IPC_PRINTF("FT mode is CUJU_FT_INIT from %08x\n", base_nic);
			/* create new thread for snapshot */

			vm_data = add_vm_target(&vm_head.vm_list, base_nic, 0x0, NULL);
			if (!vm_data) {
				perror("could not create snapshot data");
				goto error_handle;
			}

			vm_data->ipc_socket = sock;
			vm_data->fault_enable = 1;
			vm_data->nic[0] = base_nic;
			printf("[FT_INIT] vm_data: %p\n", vm_data);

			if (pthread_create(&thread_snapshot, NULL, ipc_snapshot_in, (void *)vm_data) < 0) {
				perror("could not create snapshot thread");
				goto error_handle;
			}
		}
#endif

#if USING_NETLINK
		nl_ipc.epoch_id = ipc_ptr->epoch_id;
		nl_ipc.flush_id = ipc_ptr->flush_id;
		nl_ipc.cuju_ft_mode = ipc_ptr->cuju_ft_mode;
		nl_ipc.nic_count = ipc_ptr->nic_count;

		memcpy(NLMSG_DATA(nlh), &nl_ipc, sizeof(nl_ipc));

		//strcpy(NLMSG_DATA(nlh), (void *)&nl_ipc);

		if (sendmsg(sock_fd, &msg, 0) < 0) {
			perror("send msg failed!\n");
			free(nlh);
			close(sock_fd);
			goto error_handle;
		}
#endif

		//MSG_PRINTF("NIC Cnt:%d\n", ipc_ptr->nic_count);
		//MSG_PRINTF("CONN Cnt:%d\n", ipc_ptr->conn_count);
		//MSG_PRINTF("IP:%08x\n", *(u_int32_t*)ipc_ptr->nic[0]);
#if 0
		if (ipc_ptr->nic_count) {
			for (int idx = 0; idx < ipc_ptr->nic_count; idx++) {
				guest_ip_db = ntohl(*((u_int32_t *)(client_message + sizeof(struct proto_ipc)) + idx));

				((u_int32_t *)ipt_addr + sizeof(struct proto_ipc) + idx)
				MSG_PRINTF("Find IP String %08x\n", guest_ip_db);

			}
		}
#endif

		//clear the message buffer
		memset(client_message, 0, sizeof(struct proto_ipc));
		read_size = 0;

		//printf("NIC IP2:%08x\n", ipt_addr->nic[0]);
	}

	if (read_size == 0) {
		IPC_PRINTF("Client disconnected\n");

		if (shm_idx != 0) {
			struct fo_list *new = malloc(sizeof(struct fo_list));
			IPC_PRINTF("insert shm id\n");
			new->nic = base_nic;
			new->socket_id = shm_idx;
			LIST_ADDQ(&fo_head.fo_list, &new->fo_list);
			total_ipc_idx--;
		}

		fflush(stdout);
		goto error_handle;
	} else if (read_size == -1) {
		perror("recv failed");
	}

error_handle:
#if USING_NETLINK
	free(nlh);
#endif	
	close(sock);

	pthread_join(thread_snapshot, NULL);

	IPC_PRINTF("Close Thread\n");
	printf("[%s] Close Thread\n", __func__);
	
	pthread_exit(NULL);
	//return NULL;
}
#if USING_SNAPSHOT_THREAD

int ipc_dump_tcp(struct vm_list *vm_target)
{
	struct vm_list *target;
	struct vmsk_list *target_sk;

	IPC_TH_PRINTF("========================= START =========================\n");

	if (vm_target->socket_count) {
		printf("IP:%08x:\n", vm_target->vm_ip);

		list_for_each_entry(target_sk, &vm_target->skid_head.skid_list, skid_list) {
			printf("\tSocket ID:%08x\n", target_sk->socket_id);

			dump_tcp_conn_state_conn(target_sk->socket_id, &(target_sk->sk_data),
						 target_sk->conn);

		}
	}

	IPC_TH_PRINTF("========================= END =========================\n");

	return 0;
}
/*
int sync_fd_state(struct vm_list *vm_target, struct dt_info *buf)
{
	struct vm_list *target;
	struct vmsk_list *target_sk;
	int i = 0;
	IPC_TH_PRINTF("========================= START =========================\n");

	if (vm_target->socket_count) {
		printf("IP:%08x:\n", vm_target->vm_ip);

		list_for_each_entry(target_sk, &vm_target->skid_head.skid_list, skid_list) {
			printf("\tSocket ID:%08x\n", target_sk->socket_id);

			dump_tcp_conn_state_conn(target_sk->socket_id, &(target_sk->sk_data),
						 target_sk->conn, &buf[i++]);

		}
	}

	IPC_TH_PRINTF("========================= END =========================\n");

	return 0;
}*/

/*int sync_fd_state_test(int fd, struct dt_info *buf)
{
	struct libsoccr_sk_data* data = calloc(1, sizeof(struct libsoccr_sk_data));
	struct sk_prefix *pre = calloc(1, sizeof(*pre));
	struct dt_info *buf;
	save_sk_header(pre, 1);
    int proxy_dt_fd = conn_to_backup_proxy();
	dump_send(backend_fd, proxy_dt_fd, data, pre, buf);

	return 0;
}*/

int ipc_restore_tcp(struct vm_list *vm_target)
{
	struct vm_list *target;
	struct vmsk_list *target_sk;

	IPC_TH_PRINTF("========================= START =========================\n");

	if (vm_target->socket_count) {
		printf("IP:%08x:\n", vm_target->vm_ip);

		list_for_each_entry(target_sk, &vm_target->skid_head.skid_list, skid_list) {
			printf("\tSocket ID:%08x\n", target_sk->socket_id);

			restore_one_tcp_conn(target_sk->socket_id, &(target_sk->sk_data));
		}
	}

	IPC_TH_PRINTF("========================= END =========================\n");

	return 0;
}

u_int32_t lock_for_snapshot = 0;
void ipc_snapshot_lock()
{
	//HA_SPIN_LOCK(SNAPSHOT_LOCK, &shapshot_lock);
#if 0	
	lock_for_snapshot = 1;
#endif
}

void ipc_snapshot_unlock()
{
	//HA_SPIN_UNLOCK(SNAPSHOT_LOCK, &shapshot_lock);
#if 0	
	lock_for_snapshot = 0; 	
#endif
}

void ipc_snapshot_trylock()
{
	//HA_SPIN_TRYLOCK(SNAPSHOT_LOCK, &shapshot_lock);
#if 0
	u_int32_t lock_count = 0;

	while(lock_for_snapshot) {
		lock_count++;
	}

	printf("Lock Count: %d !!!!!!!!!!!!!!!\n", lock_count);
#endif
}

void ipc_snapshot_tryunlock()
{
	//HA_SPIN_UNLOCK(SNAPSHOT_LOCK, &shapshot_lock);
	//lock_for_snapshot = 0; 	
}

void *ipc_snapshot_in(void *data)
{
	int hd_idx, len, fd;
	struct vm_list *vm_target = (struct vm_list *)data;
	struct dt_info *buf;
	struct sk_prefix *pre = malloc(sizeof(struct sk_prefix));
	u_int32_t socket_count;
	static int enter = 1;
	struct  timeval start;
	struct  timeval end;
	unsigned  long diff;

	printf("[%s] vm_data:%p  nic:%08x\n", __func__, vm_target, vm_target->nic[0]);

	while (1) {
		pthread_mutex_lock(&vm_target->ss_data.locker);
		pthread_cond_wait(&vm_target->ss_data.cond, &vm_target->ss_data.locker);

		IPC_TH_PRINTF("[%s] vm_data:%p  nic:%08x\n", __func__, vm_target, vm_target->nic[0]);
		IPC_TH_PRINTF("[%s] fake socket:%d\n\n\n", __func__, vm_target->nic[1]);
		IPC_TH_PRINTF("[%s] real socker count:%d\n\n\n", __func__, vm_target->socket_count);
		
		pthread_mutex_lock(&(vm_target->socket_metux));	
		
		if (vm_target->failovered) {
			printf("[%s] failovered:%d\n", __func__, vm_target->failovered);

			////restore_one_tcp_conn();
			//ipc_restore_tcp(vm_target);
		} else {

			if (vm_target->socket_count) {
				//printf("[%s] real socket count:%d\n\n\n", __func__, vm_target->socket_count);
				/*
				save_sk_header(pre, vm_target->socket_count);
				buf = calloc(pre->conn_size, sizeof(*buf));
				sync_fd_state(vm_target, buf);  //ipc_dump_tcp
				hd_idx = sizeof(struct sk_prefix);
				len = sizeof(struct sk_prefix) + pre->conn_size*(sizeof(struct sk_addr)+sizeof(struct libsoccr_sk_data));
				char *send_data = malloc(len);

				memcpy(send_data, pre, sizeof(struct sk_prefix));

				for(int i = 0; i < pre->conn_size; i++)        //for loop to store send out buf
				{
					send_data = realloc(send_data, len + buf[i].sk_data.outq_len + buf[i].sk_data.inq_len);
					final_save_data(send_data, &buf[i], hd_idx, len);
					len += buf[i].sk_data.inq_len + buf[i].sk_data.outq_len;
					hd_idx += (sizeof(struct sk_addr)+sizeof(struct libsoccr_sk_data)) ;
				}
				if(enter)
				{
					fd = socket(AF_INET, SOCK_STREAM, 0);
					struct sockaddr_in proxy_backup_addr;
					bzero(&proxy_backup_addr, sizeof(proxy_backup_addr));
					proxy_backup_addr.sin_family = AF_INET;
					proxy_backup_addr.sin_addr.s_addr = global.backup_addr;
					proxy_backup_addr.sin_port = htons(8000);	//need modify 
					if (connect(fd, (struct sockaddr_in*)&proxy_backup_addr, sizeof(proxy_backup_addr)) != 0) {
						printf("connection with the proxy failed !!!!!!...\n");
						exit(0);
					}
					else
						printf("connected to the proxy ~~~~~~~~~\n");
					enter = 0;
				}
				write(fd, send_data, len);*/
				//print_info(buf);
				//free(buf);
				if(enter)
				{
					fd = socket(AF_INET, SOCK_STREAM, 0);
					struct sockaddr_in proxy_backup_addr;
					bzero(&proxy_backup_addr, sizeof(proxy_backup_addr));
					proxy_backup_addr.sin_family = AF_INET;
					proxy_backup_addr.sin_addr.s_addr = global.backup_addr;
					proxy_backup_addr.sin_port = htons(4000);	//need modify 
					if (connect(fd, (struct sockaddr_in*)&proxy_backup_addr, sizeof(proxy_backup_addr)) != 0) {
						printf("connection with the proxy failed !!!!!!...\n");
						exit(0);
					}
					else
						printf("connected to the proxy ~~~~~~~~~\n");
					enter = 0;
				}
				struct libsoccr_sk_data* data = calloc(1, sizeof(struct libsoccr_sk_data));

				save_sk_header(pre, 1);
				dump_send(frontend_fd, fd, data, pre, buf);
				//free(data);
				/*------------------------------------------------------------------*/
				data = calloc(1, sizeof(struct libsoccr_sk_data));
				
				save_sk_header(pre, 1);
				gettimeofday(&start,NULL);
				dump_send(backend_fd, fd, data, pre, buf);
				gettimeofday(&end,NULL);
				diff = 1000000 * (end.tv_sec-start.tv_sec)+ end.tv_usec-start.tv_usec;
				printf("the difference is %ld\n",diff);
				//free(data);
				
			}



			/* send end of snapshot to Cuju */
			//printf("send end of snapshot to Cuju \n");
			write(vm_target->ipc_socket, &socket_count, sizeof(socket_count));			
		
		}
		
		pthread_mutex_unlock(&(vm_target->socket_metux));			
		
		//show_target_rule(&vm_head.vm_list);

		/* send end of snapshot to Cuju */


		pthread_mutex_unlock(&vm_target->ss_data.locker);
	}


	printf("[%s]\n", __func__);

func_error:
	pthread_exit(NULL);
}
#endif
#endif

#if USING_TCP_REPAIR

void release_sk(struct libsoccr_sk *sk)
{

	free(sk->recv_queue);
	free(sk->send_queue);
	//free(sk->src_addr);	// the addr is local pointer, so needn't free.
	//free(sk->dst_addr);
	free(sk);
}

void set_addr_port_conn(struct libsoccr_sk *socr, struct connection *conn)
{
	union libsoccr_addr sa_src, sa_dst;
	struct sockaddr_in src_addr, dst_addr;

	struct in_addr ipv4_to;
	struct in_addr ipv4_from;
	in_port_t ipv4_to_port;
	in_port_t ipv4_from_port;

	ipv4_to.s_addr = ((struct sockaddr_in *)&conn->addr.to)->sin_addr.s_addr;
	ipv4_from.s_addr = ((struct sockaddr_in *)&conn->addr.from)->sin_addr.s_addr;

	ipv4_to_port = ((struct sockaddr_in *)&conn->addr.to)->sin_port;
	ipv4_from_port = ((struct sockaddr_in *)&conn->addr.from)->sin_port;

	src_addr.sin_addr.s_addr = ipv4_from.s_addr;
	dst_addr.sin_addr.s_addr = ipv4_to.s_addr;

	if (restore_sockaddr(&sa_src,
			     AF_INET, ipv4_from_port,
			     &src_addr.sin_addr.s_addr, 0) < 0)
		return;

	if (restore_sockaddr(&sa_dst,
			     AF_INET, ipv4_to_port,
			     &dst_addr.sin_addr.s_addr, 0) < 0)
		return;

	libsoccr_set_addr(socr, 1, &sa_src, 0);
	libsoccr_set_addr(socr, 0, &sa_dst, 0);
}

int dump_tcp_conn_state_conn(int fd, struct sk_data_info *sk_data,
			     struct connection *conn, struct dt_info* buf)

{
	int ret;
	struct libsoccr_sk_data *data = &(sk_data->sk_data);

	sk_data->libsoccr_sk = malloc(sizeof(struct libsoccr_sk));

	if (tcp_repair_on(fd) < 0) {
		printf("tcp_repair_on fail.\n");
		return -1;
	}

	sk_data->libsoccr_sk->fd = fd;
	set_addr_port_conn(sk_data->libsoccr_sk, conn);


	ret = libsoccr_save(sk_data->libsoccr_sk, data, sizeof(*data));


	if (ret < 0) {
		printf("libsoccr_save() failed with %d\n", ret);
		return ret;
	}
	if (ret != sizeof(*data)) {
		printf("This libsocr is not supported (%d vs %d)\n",
		       ret, (int)sizeof(*data));
		return ret;
	}

	if (tcp_repair_off(fd) < 0) {
		printf("tcp_repair_off fail.\n");
		return -1;
	}

	
#if SAVE_SOCKET_STATE
	save_sk_data(data, sk_data->libsoccr_sk, buf);
#endif

	return ret;
}

/******************************** REPAIR RESTORE ********************************/

static int restore_tcp_conn_state_conn(int fd, struct sk_data_info *data)
{
	//int aux;
	union libsoccr_addr sa_src, sa_dst;
	//print_info(data);

	if (restore_sockaddr(&sa_src,
			     AF_INET, data->sk_addr.src_port,
			     &data->sk_addr.src_addr, 0) < 0)
		goto err;
	if (restore_sockaddr(&sa_dst,
			     AF_INET, data->sk_addr.dst_port,
			     &data->sk_addr.dst_addr, 0) < 0)
		goto err;

	libsoccr_set_addr(data->libsoccr_sk, 1, &sa_src, 0);
	libsoccr_set_addr(data->libsoccr_sk, 0, &sa_dst, 0);

	if (libsoccr_restore_conn(data, sizeof(*data)))
		goto err;

	return 0;

err:
	return -1;
}

int restore_one_tcp_conn(int fd, struct sk_data_info *data)
{
	//struct libsoccr_sk *sk;

	printf("Restoring TCP connection\n");

	data->libsoccr_sk = libsoccr_pause(fd);
	if (!data->libsoccr_sk)
		return -1;

	if (restore_tcp_conn_state_conn(fd, data)) {
		libsoccr_release(data->libsoccr_sk);
		return -1;
	}
	release_sk(data->libsoccr_sk);
	return 0;
}

#endif /* USING_TCP_REPAIR */