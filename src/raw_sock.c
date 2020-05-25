/*
 * RAW transport layer over SOCK_STREAM sockets.
 *
 * Copyright 2000-2012 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <netinet/tcp.h>

#include <common/buffer.h>
#include <common/compat.h>
#include <common/config.h>
#include <common/debug.h>
#include <common/standard.h>
#include <common/ticks.h>
#include <common/time.h>

#include <proto/connection.h>
#include <proto/fd.h>
#include <proto/freq_ctr.h>
#include <proto/log.h>
#include <proto/pipe.h>
#include <proto/raw_sock.h>
#include <proto/stream_interface.h>
#include <proto/task.h>

#include <types/global.h>
#include <types/cuju_ft.h>
#include <libs/soccr.h>

#if defined(USE_LINUX_SPLICE)
#include <common/splice.h>

#define PIPE_ASSERT 1

#if PIPE_ASSERT
#include <assert.h>
#endif

#define DEBUG_SOCK_RAW 1
#if DEBUG_SOCK_RAW
#define DSRPRINTF(x...) printf(x)
#else
#define DSRPRINTF(x...)
#endif


#define DEBUG_RS_LIST 0
#if DEBUG_RS_LIST
#define RSLPRINTF(x...) printf(x)
#else
#define RSLPRINTF(x...)
#endif

#define DEBUG_SOCK_BUF 0
#if DEBUG_SOCK_BUF
#define DSBUFPRINTF(x...) printf(x)
#else
#define DSBUFPRINTF(x...)
#endif


#define DEBUG_SHM_FLAGS 0
#if DEBUG_SHM_FLAGS
#define SHMFPRINTF(x...) printf(x)
#else
#define SHMFPRINTF(x...)
#endif


/* A pipe contains 16 segments max, and it's common to see segments of 1448 bytes
 * because of timestamps. Use this as a hint for not looping on splice().
 */
#define SPLICE_FULL_HINT	16*1448

/* how many data we attempt to splice at once when the buffer is configured for
 * infinite forwarding */

#define MAX_SPLICE_AT_ONCE	(1<<30)
double time_taken = 0.0;
u_int16_t next_pipe_cnt = 0;

struct timeval time_flush;
struct timeval time_flush_end;
unsigned long flush_time;

struct timeval time_dup;
struct timeval time_dup_end;
unsigned long dup_time;

struct timeval time_transfer;
struct timeval time_transfer_end;
unsigned long transfer_time;	
unsigned int transfer_cnt;
unsigned int transfer_data_cnt;

struct timeval time_az;
struct timeval time_az_end;
unsigned long time_azone;	

struct timeval time_bz;
struct timeval time_bz_end;
unsigned long time_bzone;	

struct timeval time_cz;
struct timeval time_cz_end;
unsigned long time_czone;	

struct timeval time_dz;
struct timeval time_dz_end;
unsigned long time_dzone;	

struct timeval time_a_other;
struct timeval time_a_other_end;
unsigned long a_other_time;	

struct timeval time_cz_other;
struct timeval time_cz_other_end;
unsigned long cz_other_time;

struct timeval time_tdump;
struct timeval time_tdump_end;
unsigned long tdump_time;	

struct table* t;


static struct timeval timeval_current(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv;
}

static double timeval_elapsed(struct timeval *tv)
{
	struct timeval tv2 = timeval_current();
	return (tv2.tv_sec - tv->tv_sec) + 
	       (tv2.tv_usec - tv->tv_usec)*1.0e-6;
}

struct table *createTable(int size){
    struct table *t = (struct table*)malloc(sizeof(struct table));
    t->size = size;
    t->list = (struct node**)malloc(sizeof(struct node*)*size);
    int i;
    for(i=0;i<size;i++)
        t->list[i] = NULL;
    return t;
}
int hashCode(struct table *t,int key){
    if(key<0)
        return -(key%t->size);
    return key%t->size;
}
void insert(struct table *t,int key,int val){
    int pos = hashCode(t,key);
    struct node *list = t->list[pos];
    struct node *newNode = (struct node*)malloc(sizeof(struct node));
    struct node *temp = list;
    while(temp){
        if(temp->key==key){
            temp->val = val;
            return;
        }
        temp = temp->next;
    }
    newNode->key = key;
    newNode->val = val;
    newNode->next = list;
    t->list[pos] = newNode;
}
int lookup(struct table *t,int key){
    int pos = hashCode(t,key);
    struct node *list = t->list[pos];
    struct node *temp = list;
    while(temp){
        if(temp->key==key){
            return temp->val;
        }
        temp = temp->next;
    }
    return -1;
}


/* Returns :
 *   -1 if splice() is not supported
 *   >= 0 to report the amount of spliced bytes.
 *   connection flags are updated (error, read0, wait_room, wait_data).
 *   The caller must have previously allocated the pipe.
 */
int raw_sock_to_pipe(struct connection *conn, void *xprt_ctx, struct pipe *pipe, unsigned int count)
{
	int ret;
	int retval = 0;
	struct in_addr ipv4_to;
	in_port_t ipv4_to_port;
	struct in_addr ipv4_from;
	in_port_t ipv4_from_port;
	struct guest_ip_list* guest_info = NULL;
	//uint32_t epoch_id = 0;
	//uint32_t flush_id = 0;

	if (!conn_ctrl_ready(conn))
		return 0;

	if (!fd_recv_ready(conn->handle.fd))
		return 0;

	//printf("[%s] Enter ID:%d\n", __func__, pthread_self());

	conn_refresh_polling_flags(conn);
	errno = 0;

#if ENABLE_CUJU_FT
	pipe->in_fd = conn->handle.fd;
#endif

	/* Under Linux, if FD_POLL_HUP is set, we have reached the end.
	 * Since older splice() implementations were buggy and returned
	 * EAGAIN on end of read, let's bypass the call to splice() now.
	 */
	if (unlikely(!(fdtab[conn->handle.fd].ev & FD_POLL_IN))) {
		/* stop here if we reached the end of data */
		if ((fdtab[conn->handle.fd].ev & (FD_POLL_ERR|FD_POLL_HUP)) == FD_POLL_HUP)
			goto out_read0;

		/* report error on POLL_ERR before connection establishment */
		if ((fdtab[conn->handle.fd].ev & FD_POLL_ERR) && (conn->flags & CO_FL_WAIT_L4_CONN)) {
			conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
			errno = 0; /* let the caller do a getsockopt() if it wants it */
			goto leave;
		}
	}
	
	ipv4_to.s_addr = ntohl(((struct sockaddr_in *)&conn->addr.to)->sin_addr.s_addr);
	ipv4_from.s_addr = ntohl(((struct sockaddr_in *)&conn->addr.from)->sin_addr.s_addr);

	ipv4_to_port = ntohs(((struct sockaddr_in *)&conn->addr.to)->sin_port);
	ipv4_from_port = ntohs(((struct sockaddr_in *)&conn->addr.from)->sin_port);	

	//printf("NETLINK IP:%08x Port:%04x\n", ntohl(ipv4_to.s_addr), ntohs(ipv4_to_port));


#if USING_SHM_IPC
	if (!conn->shm_idx) {
		conn->shm_idx = getshmid(ipv4_from.s_addr, ipv4_to.s_addr, &conn->direction);
	
		if (conn->shm_idx == 0) {
			SHMFPRINTF("IPC SHM ID is zero\n");
		}
	}

    SHMFPRINTF("IPC Epoch ID:%d\n", (ipt_target + conn->shm_idx)->epoch_id);
	SHMFPRINTF("IPC Flush ID:%d\n", (ipt_target + conn->shm_idx)->flush_id);
	SHMFPRINTF("DIRECTION :%d\n", conn->direction);
#else
	if (!conn->conn_gipl) {
		guest_info = check_guestip(ipv4_from.s_addr, ipv4_to.s_addr, &conn->direction);
		conn->conn_gipl = guest_info;
	}
	else {
		guest_info = conn->conn_gipl;
	}
#endif

	while (count) {
		if (count > MAX_SPLICE_AT_ONCE)
			count = MAX_SPLICE_AT_ONCE;

		ret = splice(conn->handle.fd, NULL, pipe->prod, NULL, count,
					 SPLICE_F_MOVE|SPLICE_F_NONBLOCK);

		if (ret <= 0) {
			if (ret == 0)
				goto out_read0;

			if (errno == EAGAIN) {
				/* there are two reasons for EAGAIN :
				 *   - nothing in the socket buffer (standard)
				 *   - pipe is full
				 * The difference between these two situations
				 * is problematic. Since we don't know if the
				 * pipe is full, we'll stop if the pipe is not
				 * empty. Anyway, we will almost always fill or
				 * empty the pipe.
				 */
				if (pipe->data) {
					/* alway stop reading until the pipe is flushed */
					conn->flags |= CO_FL_WAIT_ROOM;
					break;
				}

				fd_cant_recv(conn->handle.fd);
				break;
			}
			else if (errno == ENOSYS || errno == EINVAL || errno == EBADF) {
				/* splice not supported on this end, disable it.
				 * We can safely return -1 since there is no
				 * chance that any data has been piped yet.
				 */
				retval = -1;
				goto leave;
			}
			else if (errno == EINTR) {
				/* try again */
				continue;
			}
			/* here we have another error */
			conn->flags |= CO_FL_ERROR;
			break;
		} /* ret <= 0 */

		/* Recv the Data tag epoch id*/
		//if ((pipe->epoch_idx == 0) && (conn->direction == DIR_DEST_CLIENT)) {
		if (conn->direction == DIR_DEST_CLIENT) {
#if USING_SHM_IPC
			pipe->epoch_id = (ipt_target + conn->shm_idx)->epoch_id;
#else
			pipe->epoch_id = guest_info->gctl_ipc.epoch_id;
#endif
			pipe->epoch_idx = 1; 
			DSRPRINTF("%s: %p epochid:%lu\n", __func__, pipe, pipe->epoch_id);			
		}

		retval += ret;
		pipe->data += ret;
		count -= ret;

		if (pipe->data >= SPLICE_FULL_HINT || ret >= global.tune.recv_enough) {
			/* We've read enough of it for this time, let's stop before
			 * being asked to poll.
			 */
			conn->flags |= CO_FL_WAIT_ROOM;
			fd_done_recv(conn->handle.fd);
			break;
		}
	} /* while */

	if (unlikely(conn->flags & CO_FL_WAIT_L4_CONN) && retval)
		conn->flags &= ~CO_FL_WAIT_L4_CONN;

 leave:
	if (retval > 0) {
		/* we count the total bytes sent, and the send rate for 32-byte
		 * blocks. The reason for the latter is that freq_ctr are
		 * limited to 4GB and that it's not enough per second.
		 */
		_HA_ATOMIC_ADD(&global.out_bytes, retval);
		update_freq_ctr(&global.out_32bps, (retval + 16) / 32);
	}
	return retval;

out_read0:
	conn_sock_read0(conn);

	////fd_list_migration = 0;
	fdtab[conn->handle.fd].enable_migration = 0;
	empty_pipe = 1;
	DSRPRINTF("CURRENT PIPE CNT IN RELEASE:%d\n", fd_pipe_cnt);
	DSRPRINTF("Close FD:%d\n", conn->handle.fd);

	conn->flags &= ~CO_FL_WAIT_L4_CONN;
	goto leave;
}

/* Send as many bytes as possible from the pipe to the connection's socket.
 */
int raw_sock_from_pipe(struct connection *conn, void *xprt_ctx, struct pipe *pipe)
{
	int ret = 0;
	int done = 0;
	int sock_fd = 0;
	static int first_index = 0;
	static int has_create_table = 0 ;
#if ENABLE_CUJU_FT
#if !ENABLE_LIST_ADD_TAIL 
	struct pipe *pipe_trace = pipe;
#endif
	struct pipe *pipe_buf = NULL;
	struct pipe *pipe_dup = NULL;
	struct pipe *pipe_trans = pipe;
	struct pipe *pipe_last = pipe;
	//struct pipe *pipe_ted = NULL;
	int t_flag = 0;
	u_int32_t curr_flush_id;
	struct in_addr ipv4_to;
	struct in_addr ipv4_from;
	in_port_t ipv4_to_port;
	in_port_t ipv4_from_port;	

	struct guest_ip_list* guest_info = NULL;

	struct pipe *pipe_loop = NULL;
	struct pipe *pipe_idx = NULL;
	int loop_cnt = 0;
	struct proto_ipc *ipc_ptr = NULL;
	if(!has_create_table)
	{
		has_create_table = 1;
		t = createTable(5);
	}
#endif

	static struct libsoccr_sk_data sk_data;

	//printf("Send ID %d\n", conn->handle.fd);

	if (!conn_ctrl_ready(conn))
		return 0;

	if (!fd_send_ready(conn->handle.fd))
		return 0;

	conn_refresh_polling_flags(conn);

	DSRPRINTF("%s: %p\n", __func__, pipe);

#if 0
	ipv4_to = ((struct sockaddr_in *)&conn->addr.to)->sin_addr;
	ipv4_from = ((struct sockaddr_in *)&conn->addr.from)->sin_addr;
	ipv4_to_port = ((struct sockaddr_in *)&conn->addr.to)->sin_port;
	ipv4_from_port = ((struct sockaddr_in *)&conn->addr.from)->sin_port;
#endif

	ipv4_to.s_addr = ntohl(((struct sockaddr_in *)&conn->addr.to)->sin_addr.s_addr);
	ipv4_from.s_addr = ntohl(((struct sockaddr_in *)&conn->addr.from)->sin_addr.s_addr);
	ipv4_to_port = ntohs(((struct sockaddr_in *)&conn->addr.to)->sin_port);
	ipv4_from_port = ntohs(((struct sockaddr_in *)&conn->addr.from)->sin_port);	

#if USING_SHM_IPC
	if (!conn->shm_idx) {
		conn->shm_idx = getshmid(ipv4_from.s_addr, ipv4_to.s_addr, &conn->direction);
		
		if (conn->shm_idx == 0) {
			SHMFPRINTF("IPC SHM ID is zero\n");
		}
	}

    SHMFPRINTF("IPC Epoch ID:%d\n", (ipt_target + conn->shm_idx)->epoch_id);
	SHMFPRINTF("IPC Flush ID:%d\n", (ipt_target + conn->shm_idx)->flush_id);
#else
	if (!conn->conn_gipl) {
		guest_info = check_guestip(ipv4_from.s_addr, ipv4_to.s_addr, &conn->direction);
		conn->conn_gipl = guest_info;
	}
	else {
		guest_info = conn->conn_gipl;
	}
#endif

#if 0 //USING_TCP_REPAIR
 	time_tdump = timeval_current();
	dump_tcp_conn_state_conn(conn->handle.fd, &sk_data, conn);
	printf("Time of %f\n", timeval_elapsed(&time_tdump));
#endif

	////printf("conn->handle.fd: %d\n", conn->handle.fd);
#if ENABLE_CUJU_FT	
	pipe->out_fd = conn->handle.fd;

	if (pipe->data) {
		if (!first_index) {
			first_index = 1;
			//conn->pipe_buf_tail = pipe;
			printf("########FIRST RETRANSMIT########\n");
		}

		DSRPRINTF("Pipe Have Data:%d\n", pipe->data);

		if (conn->direction == DIR_DEST_GUEST) {
			DSRPRINTF("DIR_DEST_GUEST\n");
			pipe_buf = get_pipe();
			pipe_dup = get_pipe();

			if (pipe_buf == NULL) {
				printf("Use FD count:%d !!!!!!!!\n", fd_pipe_cnt);
#if PIPE_ASSERT
				assert(0);
#else
				return 0;
#endif			
			}
			if (pipe_dup == NULL) {
				printf("Use FD count:%d !!!!!!!!\n", fd_pipe_cnt);
#if PIPE_ASSERT
				assert(0);
#else
				return 0;
#endif			
			}

			ft_dup_pipe(pipe, pipe_buf, COPY_PIPE_COPY);
			ft_dup_pipe(pipe, pipe_dup, COPY_PIPE_CLEAN);

			fd_pipe_cnt+=2;
			DSRPRINTF("Create pipe 2 total:%d\n", fd_pipe_cnt);
			conn->backend_pipecnt+=2;
		}
		else if (conn->direction == DIR_DEST_CLIENT) {
			DSRPRINTF("DIR_DEST_CLIENT\n");

			pipe_buf = get_pipe();
			
			if (pipe_buf == NULL) {
				DSRPRINTF("NULL pointer\n");
#if PIPE_ASSERT
				assert(0);
#else
				return 0;
#endif			
			}

			DSRPRINTF("Get Pipe:%p\n", pipe_buf);	

			ft_dup_pipe(pipe, pipe_buf, 1);
			fd_pipe_cnt++;

			DSRPRINTF("Create pipe 1 total:%d\n", fd_pipe_cnt);
			conn->frontend_pipecnt++;
		}
		else {
			printf("No Direction/ No FT mode\n");

		}
	}
	else {
		DSRPRINTF("Pipe Have No Data\n");

		if (pipe->pipe_nxt == NULL)	{
			DSRPRINTF("########################NULL RETRANSMIT########################\n");
			goto after_send;
		}
	}

	/* enable when enter FT */
	////fdtab[conn->handle.fd].enable_migration = 1;

	if (pipe->pipe_nxt) {
		DSRPRINTF("Pipe Have NXT\n");

		/* search pipe_nxt is empty insert new incoming to the pipe buffer tail */
		next_pipe_cnt = 0;

#if !ENABLE_LIST_ADD_TAIL   /* Add list tail method */ 
		while (1) {
			if (pipe_trace->pipe_nxt == NULL) {
				if(pipe->data) {
					pipe_trace->pipe_nxt = pipe_buf;
					pipe_trace->pipe_nxt->pipe_dup = pipe_dup;
				}
				break;
			}

			next_pipe_cnt++;
	
			pipe_trace = pipe_trace->pipe_nxt;

			/* only for failover */
			if((pipe_trace->pipe_dup) && pipe_trace->pipe_dup->data &&
				!(pipe_trace->trans_suspend) && !(pipe_trace->data)) {
				ft_dup_pipe(pipe_trace->pipe_dup, pipe_trace, COPY_PIPE_COPY);
			}
		}
#else
		if (pipe_buf != NULL) {
			if (conn->pipe_buf_tail == NULL)
				conn->pipe_buf_tail = pipe;
			conn->pipe_buf_tail->pipe_nxt = pipe_buf;
			pipe_buf->pipe_dup = pipe_dup;
		}
#endif 
	}
	else {
		DSRPRINTF("Pipe Have NO NXT\n");		
		pipe->pipe_nxt = pipe_buf;
		//if (pipe->pipe_nxt)
			//pipe->pipe_nxt->pipe_dup = pipe_dup;
		conn->pipe_buf_tail = pipe->pipe_nxt;
	}
	
	done = 0;
	pipe_trans = pipe->pipe_nxt;
	pipe->data = 0;

	if (pipe_trans == NULL) { 
		DSRPRINTF("pipe_trans is NULL\n");
#if PIPE_ASSERT	
		assert(1);
#else
		return 0;
#endif
	}

	if (conn->direction == DIR_DEST_GUEST) {

#if !ENABLE_LIST_ADD_TAIL   /* Add list tail method */ 
		//curr_flush_id = ft_get_flushcnt();

#if USING_SHM_IPC
		curr_flush_id = (ipt_target + conn->shm_idx)->flush_id;
#else		
		curr_flush_id = guest_info->gctl_ipc.flush_id;
#endif

		if (pipe_trans->flush_idx) {
			DSRPRINTF("Enter Flush\n");

			/* check for release */
			ft_release_pipe_by_flush(pipe, curr_flush_id, &fd_pipe_cnt ,&conn->backend_pipecnt);

			pipe_trans = pipe->pipe_nxt;

			if (pipe_trans == NULL) {
				DSRPRINTF("pipe_trans is NULL in Flush\n");
				empty_pipe = 1;
				goto after_send;
			}
		}
		else {
			pipe_trans->flush_idx = 1;
			pipe_trans->flush_id = curr_flush_id;
		}
#else
#if USING_SHM_IPC
		curr_flush_id = (ipt_target + conn->shm_idx)->flush_id;
#else	
		curr_flush_id = guest_info->gctl_ipc.flush_id;
#endif	
		pipe_trans->flush_id = curr_flush_id;
#endif	


		transfer_cnt = 0;
		transfer_data_cnt = 0;

		/* WRITE */
		DSRPRINTF("Trans Loop %p, %d\n", pipe_trans, pipe_trans->data);
		while (pipe_trans->data) {
			if (!pipe_trans->transfered) {
				
				DSRPRINTF("pipe_trans->data:%d ID:%lu\n", pipe_trans->data, pipe_trans->flush_id);

				ret = splice(pipe_trans->cons, NULL, conn->handle.fd, NULL,
							pipe_trans->data, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);

				if (ret <= 0) {
					//pipe_trans->trans_suspend = 1;
					t_flag = (errno == EAGAIN);

					DSRPRINTF("RET is %d  t_flag is %d\n", ret, t_flag);
					if (ret == 0 || t_flag) {
						DSRPRINTF("ret == 0 || t_flag\n");
						pipe_trans->trans_suspend = 1;
						fd_cant_send(conn->handle.fd);
						break;
					}
					else if (errno == EINTR) {
						DSRPRINTF("errno == EINTR\n");
						continue;
					}

					DSRPRINTF("CO_FL_ERROR\n");
					/* here we have another error */
					conn->flags |= CO_FL_ERROR;
					break;
				}
				transfer_cnt++;
				done += ret;
				pipe_trans->data -= ret;
				pipe_trans->transfer_cnt++;
				pipe_trans->trans_suspend = 0;			
				pipe_trans->transfered = 1;
				printf("@@done:%d\n", done);
				DSRPRINTF("Transfered\n");
			}
			else {
				printf("pipe_trans->transfered\n");
			}

			if (pipe_trans->pipe_nxt != NULL) {
				RSLPRINTF("Go to next, Trans:%p\n", pipe_trans);
#if ENABLE_LIST_ADD_TAIL			
				if (pipe_trans->transfered) {
					if (conn->sent_pipe == NULL) {
						conn->sent_pipe = pipe_trans;
						conn->sent_pipe_tail = pipe_trans;
						RSLPRINTF("NULL pipe_trans:%p\n", pipe_trans);
					}
					else {
						RSLPRINTF("Link Next T:%p TN:%p pipe_trans:%p\n", conn->sent_pipe_tail, conn->sent_pipe_tail->pipe_nxt, pipe_trans); 
						conn->sent_pipe_tail->pipe_nxt = pipe_trans;
						conn->sent_pipe_tail = conn->sent_pipe_tail->pipe_nxt;
						RSLPRINTF("LE Next T:%p TN:%p pipe_trans:%p\n", conn->sent_pipe_tail, conn->sent_pipe_tail->pipe_nxt, pipe_trans);						
					}
					pipe_last->pipe_nxt = pipe_trans->pipe_nxt; 
					conn->sent_pipe_tail->pipe_nxt = NULL;
					DSRPRINTF("Transfered then goto pipe_nxt\n");
				}
				else {
					RSLPRINTF("Go to next No Transfer\n");
				}

				pipe_trans = pipe_last->pipe_nxt;
				RSLPRINTF("pipe_last:%p\n", pipe_last);
#else
				pipe_trans = pipe_trans->pipe_nxt;		
#endif
			}
			else {
				RSLPRINTF("Go to End, Trans:%p\n", pipe_trans);
				if (pipe_trans->transfered) {
#if ENABLE_LIST_ADD_TAIL					
					if (conn->sent_pipe == NULL) {
						conn->sent_pipe = pipe_trans;
						conn->sent_pipe_tail = pipe_trans;
						//pipe->pipe_nxt = NULL;
					}
					else {
						conn->sent_pipe_tail->pipe_nxt = pipe_trans;
						conn->sent_pipe_tail = conn->sent_pipe_tail->pipe_nxt;
						conn->sent_pipe_tail->pipe_nxt = NULL;
					}
					DSRPRINTF("Transfered then exit\n");
				}
				else {
					RSLPRINTF("Go Next No Transfer\n");
				}
				pipe_last->pipe_nxt = NULL; 
#endif				
				break;
			}
		}
		sock_fd = lookup(t, conn->handle.fd);
		/*if(sock_fd == -1)
		{
			printf("new conn!!!!!!\n");
			int fd = socket(AF_INET, SOCK_STREAM, 0);
			struct sockaddr_in proxy_backup_addr;
			bzero(&proxy_backup_addr, sizeof(proxy_backup_addr));
			proxy_backup_addr.sin_family = AF_INET;
			proxy_backup_addr.sin_addr.s_addr = global.backup_addr;
			proxy_backup_addr.sin_port = htons(7000);	//need modify 
			if (connect(fd, (struct sockaddr_in*)&proxy_backup_addr, sizeof(proxy_backup_addr)) != 0) {
				printf("connection with the proxy failed !!!!!!...\n");
				exit(0);
			}
			else
				printf("connected to the proxy !!!!!!..\n");
			insert(t, conn->handle.fd, fd);
			struct sync_data data;
			data.backend_fd = conn->handle.fd;
			data.done = done;
			data.th_idx = conn->shm_idx;
			data.ipc_data = *(ipt_target + conn->shm_idx);
			
			write(fd, &data, sizeof(struct sync_data));
		}
		else
		{
			printf("sock_fd:%d\n", sock_fd);
			struct sync_data data;
			data.backend_fd = conn->handle.fd;
			data.done = done;
			data.th_idx = conn->shm_idx;
			data.ipc_data = *(ipt_target + conn->shm_idx);
			write(sock_fd, &data, sizeof(struct sync_data));
		}*/

		printf("!!!done:%d\n", done);


#if DEBUG_RS_LIST
		pipe_loop = conn->sent_pipe ;
		loop_cnt = 0;
		RSLPRINTF("######################### Loop Start #########################\n");
		while (pipe_loop) {
			loop_cnt++;
			RSLPRINTF("%p(%d) -> ", pipe_loop, pipe_loop->transfered); 
			pipe_loop = pipe_loop->pipe_nxt;

			if ((loop_cnt % 8) == 0)
				RSLPRINTF("\n");

			if (pipe_loop == NULL) {
				RSLPRINTF("NULL\n");
				break;
			}
		}
		printf("########################## Loop End ##########################\n");
#endif
#if 1
		//printf ("Last Flush ID:%d Current Flsuh ID:%d\n", conn->last_flush_id, curr_flush_id);
		if (conn->last_flush_id != curr_flush_id) {
			DSRPRINTF("fd_pipe_cnt:%d\n", fd_pipe_cnt);
			pipe_loop = conn->sent_pipe ;
			loop_cnt = 0;
			conn->last_flush_id = curr_flush_id;
			RSLPRINTF("conn->sent_pipe:%p pipe_loop:%p\n", conn->sent_pipe, pipe_loop); 
			RSLPRINTF("######################### Release Start #########################\n");
			while (pipe_loop) {
				loop_cnt++;			

				pipe_idx = pipe_loop;
				pipe_loop = pipe_loop->pipe_nxt;
#if DEBUG_RS_LIST
				if (pipe_idx) {
					RSLPRINTF("Target: %p %lu FlushID:%d:%lu \n", pipe_idx, pipe_idx->flush_id, curr_flush_id, pipe_idx->flush_id);
				}
#endif
				if (pipe_idx && pipe_idx->transfered && (curr_flush_id >= pipe_idx->flush_id)) {
					RSLPRINTF("!!!Release: %p Loop:%d\n", pipe_idx, loop_cnt);
					ft_clean_pipe(pipe_idx->pipe_dup);
					////put_pipe(pipe_idx->pipe_dup);

					ft_clean_pipe(pipe_idx);
					////put_pipe(pipe_idx);

					fd_pipe_cnt-=2; 

					conn->sent_pipe = pipe_loop;
					//conn->sent_pipe_tail = pipe_loop;
				}
				else {
					conn->sent_pipe = pipe_idx;
					break; 
				}
			}
			RSLPRINTF("########################## Release End ##########################\n");
		}
		else {

		}
#endif
#if DEBUG_RS_LIST
		RSLPRINTF("######################### Check Start #########################\n");

		pipe_loop = conn->sent_pipe ;
		loop_cnt = 0;
		while (pipe_loop) {
			loop_cnt++;
			RSLPRINTF("%p(%d) -> ", pipe_loop, pipe_loop->transfered); 
			pipe_loop = pipe_loop->pipe_nxt;

			if ((loop_cnt % 8) == 0)
				RSLPRINTF("\n");

			if (pipe_loop == NULL) {
				RSLPRINTF("NULL\n");
				break;
			}
		}
		RSLPRINTF("########################## Check End ##########################\n");
#endif	
		transfer_data_cnt = done;
	}
	else if (conn->direction == DIR_DEST_CLIENT) {
#if USING_SHM_IPC
		curr_flush_id = (ipt_target + conn->shm_idx)->flush_id;
#else
		curr_flush_id = guest_info->gctl_ipc.flush_id;
#endif


		while (pipe_trans->data) {
			//if (curr_flush_id > pipe_trans->epoch_id) {
		    DSRPRINTF("curr_flush_id: %d\n", curr_flush_id);

			if (curr_flush_id >= pipe_trans->epoch_id) {	
				DSRPRINTF("Outgoing Path: transfer: %d\n", pipe_trans->data);

				ret = splice(pipe_trans->cons, NULL, conn->handle.fd, NULL,
							pipe_trans->data, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);

				if (ret <= 0) {
					//pipe_trans->trans_suspend = 1;
					t_flag = (errno == EAGAIN);

					DSRPRINTF("RET is %d t_flag is %d\n", ret, t_flag);
					if (ret == 0 || t_flag) {
						DSRPRINTF("ret == 0 || t_flag\n");
						pipe_trans->trans_suspend = 1;
						empty_pbuffer = 1;
						last_error = t_flag; 
						
						continue;
						//fd_cant_send(conn->handle.fd);
					}
					else if (errno == EINTR) {
						DSRPRINTF("errno == EINTR\n");
						continue;
					}

					//printf("CO_FL_ERROR\n");
					/* here we have another error */
					conn->flags |= CO_FL_ERROR;
					break;
				}
				DSRPRINTF("Outgoing Path: transfer data:%u\n", ret);

				if(!ret)
					assert(0);

				done += ret;
				pipe_trans->data -= ret;
				pipe_trans->transfer_cnt++;
				pipe_trans->trans_suspend = 0;
				pipe_trans->transfered = 1;
				DSRPRINTF("Transfered\n");
				/* Pipe Release for DEST */
			}
			else {
				DSRPRINTF("DIR_DEST_CLIENT Break Pipe ID is %lu < %u(now)\n", pipe_trans->epoch_id, curr_flush_id);
				empty_pbuffer = 1;
				break;
			}

			if (pipe_trans->pipe_nxt != NULL) {
#if ENABLE_LIST_ADD_TAIL	
				struct pipe *pipe_release = pipe_trans;
				
				pipe_trans = pipe_trans->pipe_nxt;
				
				if (pipe_release->transfered) {
					if (pipe_release == conn->pipe_buf_tail) {
						conn->pipe_buf_tail = NULL;
					}
					ft_clean_pipe(pipe_release);				
					////put_pipe(pipe_release);
					
				}
#else
				pipe_trans = pipe_trans->pipe_nxt;
#endif				
				DSRPRINTF("Transfered then goto pipe_nxt\n");
			}
			else {
#if ENABLE_LIST_ADD_TAIL
				if (pipe_trans->transfered) {
					if (pipe_trans == conn->pipe_buf_tail) {
						conn->pipe_buf_tail = NULL;
					}					
					ft_clean_pipe(pipe_trans);				
					////put_pipe(pipe_trans);

					pipe->pipe_nxt = NULL;
				}				
#endif
				DSRPRINTF("DIR_DEST_CLIENT Break No Next\n");
				break;
			}			
		}

#if !ENABLE_LIST_ADD_TAIL 
		if (done) {
			ft_release_pipe_by_transfer(pipe, &fd_pipe_cnt , &conn->frontend_pipecnt);
		 }
#endif		 

//
	}
	else {
		done = 0;

		while (pipe->data) {
			ret = splice(pipe->cons, NULL, conn->handle.fd, NULL, pipe->data,
						SPLICE_F_MOVE|SPLICE_F_NONBLOCK);

			if (ret <= 0) {
				if (ret == 0 || errno == EAGAIN) {
					fd_cant_send(conn->handle.fd);
					break;
				}
				else if (errno == EINTR)
					continue;

				/* here we have another error */
				conn->flags |= CO_FL_ERROR;
				break;
			}

			done += ret;
			pipe->data -= ret;
		}	
	}
#else
	done = 0;
	while (pipe->data) {
		ret = splice(pipe->cons, NULL, conn->handle.fd, NULL, pipe->data,
					 SPLICE_F_MOVE|SPLICE_F_NONBLOCK);

		if (ret <= 0) {
			if (ret == 0 || errno == EAGAIN) {
				fd_cant_send(conn->handle.fd);
				break;
			}
			else if (errno == EINTR)
				continue;

			/* here we have another error */
			conn->flags |= CO_FL_ERROR;
			break;
		}

		done += ret;
		pipe->data -= ret;
	}
#endif
	
after_send:


	if (unlikely(conn->flags & CO_FL_WAIT_L4_CONN) && done)
		conn->flags &= ~CO_FL_WAIT_L4_CONN;


#if ENABLE_CUJU_FT
	if (pipe->pipe_nxt == NULL) {
		DSRPRINTF("FD done:%d\n", conn->handle.fd);
		return done;
	}

	if (fdtab[conn->handle.fd].enable_migration) {

		//fd_list_migration = pipe_trans->out_fd;
		
		add_ft_fd(pipe_trans->out_fd);
		
		conn->flags |= CO_FL_XPRT_WR_ENA;
	}
#endif
	return done;
}

#endif /* USE_LINUX_SPLICE */

/* Receive up to <count> bytes from connection <conn>'s socket and store them
 * into buffer <buf>. Only one call to recv() is performed, unless the
 * buffer wraps, in which case a second call may be performed. The connection's
 * flags are updated with whatever special event is detected (error, read0,
 * empty). The caller is responsible for taking care of those events and
 * avoiding the call if inappropriate. The function does not call the
 * connection's polling update function, so the caller is responsible for this.
 * errno is cleared before starting so that the caller knows that if it spots an
 * error without errno, it's pending and can be retrieved via getsockopt(SO_ERROR).
 */
static size_t raw_sock_to_buf(struct connection *conn, void *xprt_ctx, struct buffer *buf, size_t count, int flags)
{
	ssize_t ret;
	size_t try, done = 0;
	struct in_addr ipv4_to;
	in_port_t ipv4_to_port;
	struct in_addr ipv4_from;
	in_port_t ipv4_from_port;
	int nl_ret = 0;

	if (!conn_ctrl_ready(conn))
		return 0;

	if (!fd_recv_ready(conn->handle.fd))
		return 0;

	DSBUFPRINTF("[%s] Enter\n", __func__);

	conn_refresh_polling_flags(conn);
	errno = 0;

	if (unlikely(!(fdtab[conn->handle.fd].ev & FD_POLL_IN))) {
		/* stop here if we reached the end of data */
		if ((fdtab[conn->handle.fd].ev & (FD_POLL_ERR|FD_POLL_HUP)) == FD_POLL_HUP)
			goto read0;

		/* report error on POLL_ERR before connection establishment */
		if ((fdtab[conn->handle.fd].ev & FD_POLL_ERR) && (conn->flags & CO_FL_WAIT_L4_CONN)) {
			conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
			goto leave;
		}
	}

	ipv4_to.s_addr = ntohl(((struct sockaddr_in *)&conn->addr.to)->sin_addr.s_addr);
	ipv4_from.s_addr = ntohl(((struct sockaddr_in *)&conn->addr.from)->sin_addr.s_addr);

	ipv4_to_port = ((struct sockaddr_in *)&conn->addr.to)->sin_port;
	ipv4_from_port = ((struct sockaddr_in *)&conn->addr.from)->sin_port;

#if USING_SHM_IPC
	if (!conn->shm_idx) {
		conn->shm_idx = getshmid(ipv4_from.s_addr, ipv4_to.s_addr, &conn->direction);
	
		if (conn->shm_idx == 0) {
			SHMFPRINTF("IPC SHM ID is zero\n");
		}	
	}

    SHMFPRINTF("IPC Epoch ID:%d\n", (ipt_target + conn->shm_idx)->epoch_id);
	SHMFPRINTF("IPC Flush ID:%d\n", (ipt_target + conn->shm_idx)->flush_id);
	SHMFPRINTF("DIRECTION :%d\n", conn->direction);

#if USING_NETLINK
	if (conn->direction == DIR_DEST_GUEST) {

    	nl_ipc.epoch_id = 0x0;
        nl_ipc.flush_id = 0x0;
        nl_ipc.cuju_ft_mode = NL_TARGET_ADD_IN;
        nl_ipc.nic_count = 0;
		nl_ipc.conn_ip = ipv4_to.s_addr;
		nl_ipc.conn_port = ntohs(ipv4_to_port);
		
		memcpy(NLMSG_DATA(nlh), &nl_ipc, sizeof(nl_ipc));

		printf("[%s] NETLINK IP:%08x Port:%04x\n", __func__, nl_ipc.conn_ip, nl_ipc.conn_port);

		nl_ret = sendmsg(nl_sock_fd, &nl_msg, 0);

		if (nl_ret < 0) {
			perror("send msg failed!\n");
			close(nl_sock_fd);
			return 0;
		}
		printf("[%s] NETLINK Result:%d\n", __func__, nl_ret);
	}
	else if (conn->direction == DIR_DEST_CLIENT) {
		/* DIR_DEST_CLIENT */ 
    	nl_ipc.epoch_id = 0x0;
        nl_ipc.flush_id = 0x0;
        nl_ipc.cuju_ft_mode = NL_TARGET_ADD_OUT;
        nl_ipc.nic_count = 0;
		nl_ipc.conn_ip = ipv4_to.s_addr;
		nl_ipc.conn_port = ntohs(ipv4_from_port);

		memcpy(NLMSG_DATA(nlh), &nl_ipc, sizeof(nl_ipc));

		printf("[%s] NETLINK IP:%08x Port:%04x\n", __func__, nl_ipc.conn_ip, nl_ipc.conn_port);

		nl_ret = sendmsg(nl_sock_fd, &nl_msg, 0);

		if (nl_ret < 0) {
			perror("send msg failed!\n");
			close(nl_sock_fd);
			return 0;
		}
		printf("[%s] NETLINK Result:%d\n", __func__, nl_ret);
	}
	else {
		SHMFPRINTF("IPC SHM ID is zero and no netlink\n");
	}
#endif


#endif	
	/* read the largest possible block. For this, we perform only one call
	 * to recv() unless the buffer wraps and we exactly fill the first hunk,
	 * in which case we accept to do it once again. A new attempt is made on
	 * EINTR too.
	 */
	while (count > 0) {
		try = b_contig_space(buf);
		if (!try)
			break;

		if (try > count)
			try = count;

		ret = recv(conn->handle.fd, b_tail(buf), try, 0);

		if (ret > 0) {
			b_add(buf, ret);
			done += ret;
			if (ret < try) {
				/* unfortunately, on level-triggered events, POLL_HUP
				 * is generally delivered AFTER the system buffer is
				 * empty, unless the poller supports POLL_RDHUP. If
				 * we know this is the case, we don't try to read more
				 * as we know there's no more available. Similarly, if
				 * there's no problem with lingering we don't even try
				 * to read an unlikely close from the client since we'll
				 * close first anyway.
				 */
				if (fdtab[conn->handle.fd].ev & FD_POLL_HUP)
					goto read0;

				if ((!fdtab[conn->handle.fd].linger_risk) ||
					(cur_poller.flags & HAP_POLL_F_RDHUP)) {
					fd_done_recv(conn->handle.fd);
					break;
				}
			}
			count -= ret;
		}
		else if (ret == 0) {
			goto read0;
		}
		else if (errno == EAGAIN || errno == ENOTCONN) {
			fd_cant_recv(conn->handle.fd);
			break;
		}
		else if (errno != EINTR) {
			conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
			break;
		}
	}

	if (unlikely(conn->flags & CO_FL_WAIT_L4_CONN) && done)
		conn->flags &= ~CO_FL_WAIT_L4_CONN;

 leave:
	return done;

read0:
	conn_sock_read0(conn);
	conn->flags &= ~CO_FL_WAIT_L4_CONN;

	/* Now a final check for a possible asynchronous low-level error
	 * report. This can happen when a connection receives a reset
	 * after a shutdown, both POLL_HUP and POLL_ERR are queued, and
	 * we might have come from there by just checking POLL_HUP instead
	 * of recv()'s return value 0, so we have no way to tell there was
	 * an error without checking.
	 */
	if (unlikely(fdtab[conn->handle.fd].ev & FD_POLL_ERR))
		conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
	goto leave;
}

/* Send up to <count> pending bytes from buffer <buf> to connection <conn>'s
 * socket. <flags> may contain some CO_SFL_* flags to hint the system about
 * other pending data for example, but this flag is ignored at the moment.
 * Only one call to send() is performed, unless the buffer wraps, in which case
 * a second call may be performed. The connection's flags are updated with
 * whatever special event is detected (error, empty). The caller is responsible
 * for taking care of those events and avoiding the call if inappropriate. The
 * function does not call the connection's polling update function, so the caller
 * is responsible for this. It's up to the caller to update the buffer's contents
 * based on the return value.
 */
static size_t raw_sock_from_buf(struct connection *conn, void *xprt_ctx, const struct buffer *buf, size_t count, int flags)
{
	ssize_t ret;
	size_t try, done;
	int send_flag;

	if (!conn_ctrl_ready(conn))
		return 0;

	if (!fd_send_ready(conn->handle.fd))
		return 0;

	DSBUFPRINTF("[%s] Enter\n", __func__);

	conn_refresh_polling_flags(conn);
	done = 0;
	/* send the largest possible block. For this we perform only one call
	 * to send() unless the buffer wraps and we exactly fill the first hunk,
	 * in which case we accept to do it once again.
	 */
	while (count) {
		try = b_contig_data(buf, done);
		if (try > count)
			try = count;

		send_flag = MSG_DONTWAIT | MSG_NOSIGNAL;
		if (try < count || flags & CO_SFL_MSG_MORE)
			send_flag |= MSG_MORE;

		ret = send(conn->handle.fd, b_peek(buf, done), try, send_flag);

		if (ret > 0) {
			count -= ret;
			done += ret;

			/* A send succeeded, so we can consier ourself connected */
			conn->flags |= CO_FL_CONNECTED;
			/* if the system buffer is full, don't insist */
			if (ret < try)
				break;
		}
		else if (ret == 0 || errno == EAGAIN || errno == ENOTCONN || errno == EINPROGRESS) {
			/* nothing written, we need to poll for write first */
			fd_cant_send(conn->handle.fd);
			break;
		}
		else if (errno != EINTR) {
			conn->flags |= CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH;
			break;
		}
	}
	if (unlikely(conn->flags & CO_FL_WAIT_L4_CONN) && done)
		conn->flags &= ~CO_FL_WAIT_L4_CONN;

	if (done > 0) {
		/* we count the total bytes sent, and the send rate for 32-byte
		 * blocks. The reason for the latter is that freq_ctr are
		 * limited to 4GB and that it's not enough per second.
		 */
		_HA_ATOMIC_ADD(&global.out_bytes, done);
		update_freq_ctr(&global.out_32bps, (done + 16) / 32);
	}
	return done;
}

static int raw_sock_subscribe(struct connection *conn, void *xprt_ctx, int event_type, void *param)
{
	return conn_subscribe(conn, xprt_ctx, event_type, param);
}

static int raw_sock_unsubscribe(struct connection *conn, void *xprt_ctx, int event_type, void *param)
{
	return conn_unsubscribe(conn, xprt_ctx, event_type, param);
}

/* We can't have an underlying XPRT, so just return -1 to signify failure */
static int raw_sock_remove_xprt(struct connection *conn, void *xprt_ctx, void *toremove_ctx, const struct xprt_ops *newops, void *newctx)
{
	/* This is the lowest xprt we can have, so if we get there we didn't
	 * find the xprt we wanted to remove, that's a bug
	 */
	BUG_ON(1);
	return -1;
}

/* transport-layer operations for RAW sockets */
static struct xprt_ops raw_sock = {
	.snd_buf  = raw_sock_from_buf,
	.rcv_buf  = raw_sock_to_buf,
	.subscribe = raw_sock_subscribe,
	.unsubscribe = raw_sock_unsubscribe,
	.remove_xprt = raw_sock_remove_xprt,
#if defined(USE_LINUX_SPLICE)
	.rcv_pipe = raw_sock_to_pipe,
	.snd_pipe = raw_sock_from_pipe,
#endif
	.shutr    = NULL,
	.shutw    = NULL,
	.close    = NULL,
	.name     = "RAW",
};

__attribute__((constructor)) 
static void __raw_sock_init(void)
{
	xprt_register(XPRT_RAW, &raw_sock);
}

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
