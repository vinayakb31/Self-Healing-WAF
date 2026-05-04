import sysv_ipc
import struct
import time

# Must match the key in C++ exactly
KEY = 0x1234

# Must match the WAFPayload struct layout exactly
# 'i' = int (4 bytes) for ready flag
# '16s' = 16 char bytes for method
# '256s' = 256 char bytes for uri
# '4096s' = 4096 char bytes for body
STRUCT_FORMAT = 'i 16s 256s 4096s'
STRUCT_SIZE   = struct.calcsize(STRUCT_FORMAT)

print(f"Connecting to shared memory with key 0x{KEY:X}...")

try:
    # Attach to the SAME shared memory C++ created
    shm = sysv_ipc.SharedMemory(KEY)
    print("Connected! Waiting for data from C++...\n")

    while True:
        # Read raw bytes from shared memory
        raw = shm.read(STRUCT_SIZE, 0)

        # Unpack bytes into our fields
        ready, method, uri, body = struct.unpack(STRUCT_FORMAT, raw)

        if ready == 1:
            # Decode bytes to string, strip null characters
            method = method.decode('utf-8').rstrip('\x00')
            uri    = uri.decode('utf-8').rstrip('\x00')
            body   = body.decode('utf-8').rstrip('\x00')

            print("=== WAF Payload received from C++ ===")
            print(f"  Method : {method}")
            print(f"  URI    : {uri}")
            print(f"  Body   : {body}")
            print("=====================================\n")

        time.sleep(1)

except sysv_ipc.ExistentialError:
    print("ERROR: Shared memory not found!")
    print("Make sure shm_write is running first.")
