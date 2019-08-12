#ifndef _TYPES_CUKU_FT_H
#define _TYPES_CUKU_FT_H

#include <types/cuju_ft_def.h>
#include <proto/pipe.h>

extern int pb_event;

#define IP_LENGTH 4
#define DEFAULT_NIC_CNT 3
#define CONNECTION_LENGTH 12
#define DEFAULT_CONN_CNT 3
//#define DEFAULT_IPC_ARRAY  (24+(IP_LENGTH*DEFAULT_NIC_CNT)+(CONNECTION_LENGTH*DEFAULT_CONN_CNT))

#define TOTAL_NIC   8
#define TOTAL_CONN   8
#define DEFAULT_IPC_ARRAY  (20+(IP_LENGTH*TOTAL_NIC)+(CONNECTION_LENGTH*TOTAL_CONN))


#if ENABLE_CUJU_FT
extern struct proto_ipc *ipt_target;

extern u_int16_t fd_list_migration;
extern u_int32_t fd_pipe_cnt;
extern u_int16_t empty_pipe;
extern u_int16_t empty_pbuffer;
extern u_int16_t last_error;
extern u_int32_t guest_ip_db;

extern u_int16_t ipc_fd;

extern int trace_cnt;
extern int flush_cnt;

#if ENABLE_TIME_MEASURE_EPOLL	
extern struct timeval time_tepoll;
extern struct timeval time_tepoll_end;
extern unsigned long tepoll_time;	
#endif
#if ENABLE_TIME_MEASURE	

extern struct timeval time_poll;

extern struct timeval time_release;
extern struct timeval time_release_end;
extern unsigned long release_time;	

extern struct timeval time_loop;
extern struct timeval time_loop_end;
extern unsigned long loop_time;	

extern struct timeval time_recv;
extern struct timeval time_recv_end;
extern unsigned long time_in_recv;	

extern struct timeval time_send;
extern struct timeval time_send_end;
extern unsigned long time_in_send;	

extern struct timeval time_sicsp;
extern struct timeval time_sicsp_end;
extern unsigned long time_in_sicsp;	

extern struct timeval time_sicsio_send;
extern struct timeval time_sicsio_send_end;
extern unsigned long time_in_sicsio_send;	

extern struct timeval time_sicsio_recv;
extern struct timeval time_sicsio_recv_end;
extern unsigned long time_in_sicsio_recv;	

extern struct timeval time_sicsp_send;
extern struct timeval time_sicsp_send_end;
extern unsigned long time_in_sicsp_send;	

extern struct timeval time_sicsp_int;
extern struct timeval time_sicsp_int_end;
extern unsigned long time_in_sicsp_int;

#endif

#if ENABLE_CUJU_IPC

/* ipc_mode */
#define IPC_PACKET_CNT 1
#define IPC_PACKET_SIZE 2
#define IPC_TIME 3
#define IPC_SIGNAL 4
#define IPC_CUJU 5


#define COPY_PIPE_COPY 0
#define COPY_PIPE_CLEAN 1

/* cuju_ft_mode */
enum CUJU_FT_MODE
{
    CUJU_FT_ERROR = -1,
    CUJU_FT_OFF,
    CUJU_FT_INIT, // 1
    CUJU_FT_TRANSACTION_PRE_RUN,
    CUJU_FT_TRANSACTION_ITER,
    CUJU_FT_TRANSACTION_ATOMIC,
    CUJU_FT_TRANSACTION_RECV, // 5
    CUJU_FT_TRANSACTION_HANDOVER,
    CUJU_FT_TRANSACTION_SPECULATIVE,
    CUJU_FT_TRANSACTION_FLUSH_OUTPUT,
    CUJU_FT_TRANSACTION_TRANSFER,
    CUJU_FT_TRANSACTION_SNAPSHOT, // 10
    CUJU_FT_TRANSACTION_RUN,
};

/* IPC PROTO */
struct proto_ipc
{
    u_int32_t ipc_mode:8;
    u_int32_t cuju_ft_arp:2;
    u_int32_t cuju_ft_mode:6;
    u_int32_t gft_id:16;
    u_int32_t epoch_id;
    u_int32_t flush_id;
    u_int32_t packet_cnt:16;
    u_int32_t packet_size:16;
    u_int32_t time_interval;
    u_int32_t nic_count:16;
    u_int32_t conn_count:16;
    unsigned int nic[TOTAL_NIC];
    unsigned char conn[TOTAL_CONN][CONNECTION_LENGTH];   
};

struct guest_ip_list
{
    u_int32_t guest_ip;
    struct gctl_ipc gctl_ipc;
    struct list list;
};

struct ft_fd_list
{
    u_int16_t ft_fd;
    struct list list;
};

#endif /* End of ENABLE_CUJU_IPC*/

unsigned long ft_get_flushcnt();
unsigned long ft_get_epochcnt();
int ft_dup_pipe(struct pipe *source, struct pipe *dest, int clean);
int cuju_process(struct conn_stream *cs);
int ft_release_pipe_by_flush(struct pipe *pipe, uint32_t flush_id, uint16_t* total_pipe_cnt ,uint16_t* pipe_cnt);
int ft_release_pipe_by_transfer(struct pipe *pipe, uint16_t* total_pipe_cnt , uint16_t* pipe_cnt);
int ft_close_pipe(struct pipe *pipe,  int* pipe_cnt);
void ft_clean_pipe(struct pipe *pipe);
char *arp_get_ip(const char *req_mac);
void show_ft_time (void);
struct guest_ip_list *find_guestip_ptr(u_int32_t guest_ip);
u_int8_t find_guestip_exist(u_int32_t guest_ip);
struct guest_ip_list* add_guestip(u_int32_t guest_ip);
u_int8_t del_guestip(u_int32_t guest_ip);
struct guest_ip_list* check_guestip(u_int32_t source, u_int32_t dest, uint8_t* dir);
u_int8_t add_ft_fd(u_int16_t ftfd);
u_int16_t get_ft_fd(void);
__u64 tv_to_us(const struct timeval* tv);
#endif

#endif
