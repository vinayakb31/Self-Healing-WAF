import struct
import time

import sysv_ipc

SHM_KEY = 0x1234
SEM_KEY = 0x5678
BUFFER_SIZE = 10

HEADER_FORMAT = "i i i i"
SLOT_FORMAT = "i i 16s 256s 4096s"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
SLOT_SIZE = struct.calcsize(SLOT_FORMAT)


def decode_field(raw):
    return raw.decode("utf-8", errors="replace").rstrip("\x00")


print("Circular buffer reader starting...")
print(f"Slot size: {SLOT_SIZE} bytes")
print(f"Total buffer size: {HEADER_SIZE + SLOT_SIZE * BUFFER_SIZE} bytes\n")

shm = sysv_ipc.SharedMemory(SHM_KEY)
sem = sysv_ipc.Semaphore(SEM_KEY)

print("Connected! Waiting for Nginx to write requests...\n")

while True:
    payload = None

    sem.acquire()
    try:
        header_raw = shm.read(HEADER_SIZE, 0)
        write_pos, read_pos, count, next_request_id = struct.unpack(
            HEADER_FORMAT, header_raw
        )

        if count > 0:
            offset = HEADER_SIZE + (read_pos * SLOT_SIZE)
            slot_raw = shm.read(SLOT_SIZE, offset)
            ready, request_id, method, uri, body = struct.unpack(SLOT_FORMAT, slot_raw)

            if ready == 1:
                new_read_pos = (read_pos + 1) % BUFFER_SIZE
                new_count = count - 1
                shm.write(
                    struct.pack(
                        HEADER_FORMAT,
                        write_pos,
                        new_read_pos,
                        new_count,
                        next_request_id,
                    ),
                    0,
                )
                payload = (new_count, request_id, method, uri, body)
    finally:
        sem.release()

    if payload is not None:
        new_count, request_id, method, uri, body = payload
        print(f"=== Slot read (remaining in buffer: {new_count}) ===")
        print(f"  ID     : {request_id}")
        print(f"  Method : {decode_field(method)}")
        print(f"  URI    : {decode_field(uri)}")
        print(f"  Body   : {decode_field(body)}")
        print()

    time.sleep(0.3)
