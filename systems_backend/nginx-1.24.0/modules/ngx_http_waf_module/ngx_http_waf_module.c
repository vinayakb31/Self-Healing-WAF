#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/msg.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#define SHM_KEY     0x1234
#define SEM_KEY     0x5678
#define MQ_KEY      0x9ABC
#define BUFFER_SIZE 10
#define VERDICT_TIMEOUT_MS 30

typedef struct {
    int  ready;
    int  request_id;
    char method[16];
    char uri[256];
    char body[4096];
} WAFPayload;

typedef struct {
    int        write_pos;
    int        read_pos;
    int        count;
    int        next_request_id;
    WAFPayload slots[BUFFER_SIZE];
} WAFCircularBuffer;

static int              g_shmid   = -1;
static int              g_semid   = -1;
static int              g_mqid    = -1;
static WAFCircularBuffer *g_buf   = NULL;

union semun {
    int              val;
    struct semid_ds *buf;
    unsigned short  *array;
};

typedef struct {
    long mtype;
    char verdict[16];
} WAFVerdictMsg;

/* SEM_UNDO ensures lock is released even if worker crashes */
static ngx_int_t sem_lock() {
    struct sembuf op = {0, -1, SEM_UNDO};
    while (semop(g_semid, &op, 1) == -1) {
        if (errno == EINTR) continue;
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t sem_unlock() {
    struct sembuf op = {0,  1, SEM_UNDO};
    while (semop(g_semid, &op, 1) == -1) {
        if (errno == EINTR) continue;
        return NGX_ERROR;
    }
    return NGX_OK;
}

static void waf_log(const char *method, const char *uri,
                    const char *body, const char *verdict,
                    long request_id, double ms) {
    FILE *f = fopen("/tmp/waf_intercept.log", "a");
    if (f) {
        fprintf(f, "WAF HIT [%.3fms]: id=%ld verdict=%s method=%s uri=%s body=[%s]\n",
                ms, request_id, verdict, method, uri, body);
        fclose(f);
    }
}

static long waf_enqueue(const char *method, const char *uri, const char *body) {
    long request_id = 0;

    if (g_buf == NULL || g_semid < 0) {
        return 0;
    }

    if (sem_lock() != NGX_OK) {
        return 0;
    }

    if (g_buf->count < BUFFER_SIZE) {
        WAFPayload *slot = &g_buf->slots[g_buf->write_pos];
        if (g_buf->next_request_id <= 0) {
            g_buf->next_request_id = 1;
        }
        request_id = g_buf->next_request_id++;

        ngx_memzero(slot, sizeof(WAFPayload));
        slot->ready = 1;
        slot->request_id = (int) request_id;
        snprintf(slot->method, sizeof(slot->method), "%s", method);
        snprintf(slot->uri,    sizeof(slot->uri),    "%s", uri);
        snprintf(slot->body,   sizeof(slot->body),   "%s", body);
        g_buf->write_pos = (g_buf->write_pos + 1) % BUFFER_SIZE;
        g_buf->count++;
    }

    sem_unlock();
    return request_id;
}

static double waf_elapsed_ms(struct timespec *start, struct timespec *end) {
    return (end->tv_sec - start->tv_sec) * 1000.0 +
           (end->tv_nsec - start->tv_nsec) / 1e6;
}

static ngx_uint_t waf_contains_ci(const char *text, const char *needle) {
    size_t i, j;
    size_t text_len = strlen(text);
    size_t needle_len = strlen(needle);

    if (needle_len == 0 || text_len < needle_len) {
        return 0;
    }

    for (i = 0; i <= text_len - needle_len; i++) {
        for (j = 0; j < needle_len; j++) {
            char a = text[i + j];
            char b = needle[j];
            if (a >= 'A' && a <= 'Z') a = (char) (a + 32);
            if (b >= 'A' && b <= 'Z') b = (char) (b + 32);
            if (a != b) break;
        }
        if (j == needle_len) {
            return 1;
        }
    }

    return 0;
}

static ngx_uint_t waf_active_rule_match(const char *uri, const char *body) {
    if (waf_contains_ci(uri, "drop%20table")
        || waf_contains_ci(body, "drop table")
        || waf_contains_ci(uri, "union%20select")
        || waf_contains_ci(body, "union select")
        || waf_contains_ci(uri, "%24%7bjndi")
        || waf_contains_ci(uri, "${jndi:")
        || waf_contains_ci(body, "${jndi:")
        || waf_contains_ci(uri, "<script")
        || waf_contains_ci(body, "<script")
        || waf_contains_ci(uri, "../")
        || waf_contains_ci(uri, "%2e%2e%2f")
        || waf_contains_ci(uri, "/etc/passwd")
        || waf_contains_ci(body, "/etc/passwd"))
    {
        return 1;
    }

    if ((waf_contains_ci(uri, "%20or%20")
         || waf_contains_ci(uri, "+or+")
         || waf_contains_ci(body, "%20or%20")
         || waf_contains_ci(body, "+or+")
         || waf_contains_ci(body, " or "))
        && (waf_contains_ci(uri, "%3d")
            || waf_contains_ci(body, "%3d")
            || waf_contains_ci(body, "=")))
    {
        return 1;
    }

    return 0;
}

static ngx_int_t waf_wait_for_verdict(long request_id, char *verdict,
                                      size_t verdict_size) {
    struct timespec start, now, pause;
    WAFVerdictMsg msg;

    snprintf(verdict, verdict_size, "ALLOW_NO_AI");

    if (request_id <= 0 || g_mqid < 0) {
        return NGX_DECLINED;
    }

    clock_gettime(CLOCK_MONOTONIC, &start);
    pause.tv_sec = 0;
    pause.tv_nsec = 1000000;

    for (;;) {
        if (msgrcv(g_mqid, &msg, sizeof(msg.verdict),
                   request_id, IPC_NOWAIT) >= 0) {
            msg.verdict[sizeof(msg.verdict) - 1] = '\0';
            snprintf(verdict, verdict_size, "%s", msg.verdict);
            return ngx_strncmp(verdict, "DENY", 4) == 0
                   ? NGX_HTTP_FORBIDDEN
                   : NGX_DECLINED;
        }

        if (errno != ENOMSG && errno != EINTR) {
            snprintf(verdict, verdict_size, "ALLOW_MQ_ERROR");
            return NGX_DECLINED;
        }

        clock_gettime(CLOCK_MONOTONIC, &now);
        if (waf_elapsed_ms(&start, &now) >= VERDICT_TIMEOUT_MS) {
            snprintf(verdict, verdict_size, "ALLOW_TIMEOUT");
            return NGX_DECLINED;
        }

        nanosleep(&pause, NULL);
    }
}

static ngx_int_t waf_decide(const char *method, const char *uri,
                            const char *body, long *request_id,
                            char *verdict, size_t verdict_size,
                            double *ms) {
    struct timespec t1, t2;
    ngx_int_t decision;

    clock_gettime(CLOCK_MONOTONIC, &t1);

    if (waf_active_rule_match(uri, body)) {
        *request_id = 0;
        snprintf(verdict, verdict_size, "DENY_RULE");
        clock_gettime(CLOCK_MONOTONIC, &t2);
        *ms = waf_elapsed_ms(&t1, &t2);
        return NGX_HTTP_FORBIDDEN;
    }

    *request_id = waf_enqueue(method, uri, body);
    decision = waf_wait_for_verdict(*request_id, verdict, verdict_size);
    clock_gettime(CLOCK_MONOTONIC, &t2);

    *ms = waf_elapsed_ms(&t1, &t2);
    return decision;
}

static void ngx_http_waf_body_handler(ngx_http_request_t *r) {
    u_char buf[4096];
    size_t len = 0;
    long request_id = 0;
    char verdict[32];
    ngx_int_t decision;
    double ms;

    if (r->request_body && r->request_body->bufs) {
        ngx_chain_t *in;
        for (in = r->request_body->bufs; in; in = in->next) {
            ngx_buf_t *b = in->buf;
            if (b->last <= b->pos) continue;
            size_t chunk = b->last - b->pos;
            if (len + chunk >= sizeof(buf) - 1) break;
            ngx_memcpy(buf + len, b->pos, chunk);
            len += chunk;
        }
    }

    if (len == 0 && r->request_body && r->request_body->buf) {
        ngx_buf_t *b = r->request_body->buf;
        if (b->last <= b->pos) {
            buf[0] = '\0';
            goto body_done;
        }
        size_t chunk = b->last - b->pos;
        if (chunk > sizeof(buf) - 1) {
            chunk = sizeof(buf) - 1;
        }
        if (chunk > 0) {
            ngx_memcpy(buf, b->pos, chunk);
            len = chunk;
        }
    }
body_done:
    buf[len] = '\0';

    char method[16], uri[256];
    ngx_str_t request_uri = r->unparsed_uri.len ? r->unparsed_uri : r->uri;
    snprintf(method, sizeof(method), "%.*s",
             (int)r->method_name.len, r->method_name.data);
    snprintf(uri, sizeof(uri), "%.*s",
             (int)request_uri.len, request_uri.data);

    decision = waf_decide(method, uri, (char *)buf, &request_id,
                          verdict, sizeof(verdict), &ms);

    waf_log(method, uri, (char *)buf, verdict, request_id, ms);
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                  "WAF: %.3fms worker=%d id=%ld verdict=%s uri=%s",
                  ms, ngx_worker, request_id, verdict, uri);

    if (decision == NGX_HTTP_FORBIDDEN) {
        ngx_http_finalize_request(r, NGX_HTTP_FORBIDDEN);
        return;
    }

    r->write_event_handler = ngx_http_core_run_phases;
    ngx_http_core_run_phases(r);
}

static ngx_int_t ngx_http_waf_handler(ngx_http_request_t *r) {
    if (r->main->internal) return NGX_DECLINED;

    if (r->method == NGX_HTTP_POST) {
        r->main->internal = 1;
        r->request_body_in_single_buf = 1;
        r->request_body_in_clean_file = 1;
        ngx_int_t rc = ngx_http_read_client_request_body(
                            r, ngx_http_waf_body_handler);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) return rc;
        return NGX_DONE;
    }

    char method[16], uri[256];
    ngx_str_t request_uri = r->unparsed_uri.len ? r->unparsed_uri : r->uri;
    snprintf(method, sizeof(method), "%.*s",
             (int)r->method_name.len, r->method_name.data);
    snprintf(uri, sizeof(uri), "%.*s",
             (int)request_uri.len, request_uri.data);

    long request_id = 0;
    char verdict[32];
    double ms;
    ngx_int_t decision = waf_decide(method, uri, "no body", &request_id,
                                    verdict, sizeof(verdict), &ms);

    waf_log(method, uri, "no body", verdict, request_id, ms);
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                  "WAF: %.3fms worker=%d id=%ld verdict=%s uri=%s",
                  ms, ngx_worker, request_id, verdict, uri);
    return decision;
}

static ngx_int_t ngx_http_waf_init_module(ngx_cycle_t *cycle) {
    struct shmid_ds ds;
    union semun sem_arg;
    int stale_mqid;

    g_shmid = shmget(SHM_KEY, 1, 0666);
    if (g_shmid >= 0) {
        if (shmctl(g_shmid, IPC_STAT, &ds) == -1) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, errno,
                          "WAF: shmctl IPC_STAT failed");
            return NGX_ERROR;
        }

        if (ds.shm_segsz != sizeof(WAFCircularBuffer)) {
            if (shmctl(g_shmid, IPC_RMID, NULL) == -1) {
                ngx_log_error(NGX_LOG_ERR, cycle->log, errno,
                              "WAF: removing stale shm segment failed");
                return NGX_ERROR;
            }
            g_shmid = -1;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                          "WAF: removed stale shm segment");
        }
    } else if (errno != ENOENT) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, errno, "WAF: shmget failed");
        return NGX_ERROR;
    }

    if (g_shmid < 0) {
        g_shmid = shmget(SHM_KEY, sizeof(WAFCircularBuffer),
                         IPC_CREAT | IPC_EXCL | 0666);
    }
    if (g_shmid < 0) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, errno, "WAF: shmget failed");
        return NGX_ERROR;
    }

    g_semid = semget(SEM_KEY, 1, IPC_CREAT | 0666);
    if (g_semid < 0) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, errno, "WAF: semget failed");
        return NGX_ERROR;
    }

    sem_arg.val = 1;
    if (semctl(g_semid, 0, SETVAL, sem_arg) == -1) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, errno, "WAF: semctl failed");
        return NGX_ERROR;
    }

    stale_mqid = msgget(MQ_KEY, 0666);
    if (stale_mqid >= 0) {
        msgctl(stale_mqid, IPC_RMID, NULL);
    }

    g_mqid = msgget(MQ_KEY, IPC_CREAT | IPC_EXCL | 0666);
    if (g_mqid < 0) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, errno, "WAF: msgget failed");
        return NGX_ERROR;
    }

    g_buf = (WAFCircularBuffer *)shmat(g_shmid, NULL, 0);
    if (g_buf == (void *)-1) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, errno, "WAF: shmat failed");
        g_buf = NULL;
        return NGX_ERROR;
    }

    ngx_memzero(g_buf, sizeof(WAFCircularBuffer));
    g_buf->next_request_id = 1;
    shmdt(g_buf);
    g_buf = NULL;

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "WAF: circular buffer initialized by master");
    return NGX_OK;
}

static ngx_int_t ngx_http_waf_init_process(ngx_cycle_t *cycle) {
    if (g_shmid < 0) {
        g_shmid = shmget(SHM_KEY, sizeof(WAFCircularBuffer), 0666);
        if (g_shmid < 0) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, errno, "WAF: shmget failed");
            return NGX_ERROR;
        }
    }

    if (g_semid < 0) {
        g_semid = semget(SEM_KEY, 1, 0666);
        if (g_semid < 0) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, errno, "WAF: semget failed");
            return NGX_ERROR;
        }
    }

    if (g_mqid < 0) {
        g_mqid = msgget(MQ_KEY, 0666);
        if (g_mqid < 0) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, errno, "WAF: msgget failed");
            return NGX_ERROR;
        }
    }

    g_buf = (WAFCircularBuffer *)shmat(g_shmid, NULL, 0);
    if (g_buf == (void *)-1) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, errno, "WAF: shmat failed");
        g_buf = NULL;
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "WAF: worker %d ready!", ngx_worker);
    return NGX_OK;
}

static void ngx_http_waf_exit_process(ngx_cycle_t *cycle) {
    if (g_buf != NULL) {
        shmdt(g_buf);
        g_buf = NULL;
    }
}

static ngx_int_t ngx_http_waf_post_conf(ngx_conf_t *cf) {
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_handler_pt *h;
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) return NGX_ERROR;
    *h = ngx_http_waf_handler;
    return NGX_OK;
}

static ngx_http_module_t ngx_http_waf_module_ctx = {
    NULL, ngx_http_waf_post_conf,
    NULL, NULL, NULL, NULL, NULL, NULL
};

ngx_module_t ngx_http_waf_module = {
    NGX_MODULE_V1,
    &ngx_http_waf_module_ctx,
    NULL,
    NGX_HTTP_MODULE,
    NULL, ngx_http_waf_init_module,
    ngx_http_waf_init_process,
    NULL, NULL, ngx_http_waf_exit_process, NULL,
    NGX_MODULE_V1_PADDING
};
