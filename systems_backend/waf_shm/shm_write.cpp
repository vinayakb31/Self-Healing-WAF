#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/shm.h>

// This is the structure that will live in shared memory
// Both C++ and Python will use the exact same layout
struct WAFPayload {
    int  ready;        // 1 = new data available, 0 = empty
    char method[16];   // e.g. "GET" or "POST"
    char uri[256];     // e.g. "/login"
    char body[4096];   // e.g. "username=admin&password=test"
};

int main() {
    // Step 1: Create a unique key for our shared memory
    // 0x1234 is just an ID we made up — both programs must use same key
    key_t key = 0x1234;

    // Step 2: Create the shared memory segment
    // IPC_CREAT = create if doesn't exist
    // 0666 = read/write permissions for everyone
    int shmid = shmget(key, sizeof(WAFPayload), IPC_CREAT | 0666);
    if (shmid < 0) {
        perror("shmget failed");
        return 1;
    }
    std::cout << "Shared memory created! ID = " << shmid << std::endl;

    // Step 3: Attach to the shared memory (get a pointer to it)
    WAFPayload *payload = (WAFPayload *)shmat(shmid, NULL, 0);
    if (payload == (void *)-1) {
        perror("shmat failed");
        return 1;
    }
    std::cout << "Attached to shared memory!" << std::endl;

    // Step 4: Write a fake captured request into shared memory
    payload->ready = 1;
    strncpy(payload->method, "POST", sizeof(payload->method));
    strncpy(payload->uri,    "/login", sizeof(payload->uri));
    strncpy(payload->body,   "username=admin' OR '1'='1&password=x",
            sizeof(payload->body));

    std::cout << "Written to shared memory:" << std::endl;
    std::cout << "  method = " << payload->method << std::endl;
    std::cout << "  uri    = " << payload->uri    << std::endl;
    std::cout << "  body   = " << payload->body   << std::endl;
    std::cout << "Waiting for Python to read it... (press Ctrl+C to exit)" << std::endl;

    // Keep running so Python can read before memory disappears
    while (true) { sleep(1); }

    // Detach and cleanup (only reaches here if loop breaks)
    shmdt(payload);
    shmctl(shmid, IPC_RMID, NULL);
    return 0;
}
