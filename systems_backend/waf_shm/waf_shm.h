#ifndef WAF_SHM_H
#define WAF_SHM_H

#define SHM_KEY     0x1234
#define SEM_KEY     0x5678
#define MQ_KEY      0x9ABC
#define BUFFER_SIZE 10      /* 10 slots in the conveyor belt */

/* One request slot */
typedef struct {
    int  ready;
    int  request_id;
    char method[16];
    char uri[256];
    char body[4096];
} WAFPayload;

/* The full circular buffer that lives in shared memory */
typedef struct {
    int        write_pos;           /* C++ writes here */
    int        read_pos;            /* Python reads here */
    int        count;               /* how many unread slots */
    int        next_request_id;     /* unique verdict message type */
    WAFPayload slots[BUFFER_SIZE];  /* the 10 slots */
} WAFCircularBuffer;

#endif
