#!/bin/python3

import subprocess
import re
import string
import random
import statistics
import sys

# Register, Authentication
cycle_opaque_client = [0, 0]
cycle_opaque_server = [0, 0]

# OPRF, CSIKE KeyGen, CSI-FiSh KeyGen, Total
cycle_pq_reg_client = [0, 0, 0, 0]
cycle_pq_reg_server = [0, 0, 0, 0]
# OPRF, CSIKE KeyGen, CSI-FiSh sign, CSIKE Decaps, CSI-FiSh verify, Total
cycle_pq_auth_client = [0, 0, 0, 0, 0, 0]
# OPRF, CSI-FiSh verify, CSIKE encaps, CSI-FiSh sign, Total
cycle_pq_auth_server = [0, 0, 0, 0, 0]

def bench(server, dir_name, username, password, IP, Port, timeout, nroprf=False, pq=False):
    # Start OPAQUE client register
    client = "opaque-client-nroprf" if nroprf else "opaque-client"
    with open("bench/"+str(client), "a")  as client_output:
        p=subprocess.Popen([dir_name + client, IP, Port, username, password,
            "register"], stdout=client_output)
        while p.poll() is None:
                        continue
def bench2(server, dir_name, username, password, IP, Port, timeout, nroprf=False, pq=False):
    client = "opaque-client-nroprf" if nroprf else "opaque-client"
    with open("bench/"+str(client), "a")  as client_output:
        p=subprocess.Popen([dir_name + client, IP, Port, username, password,
            "authentication"], stdout=client_output)
        while p.poll() is None:
                        continue

def main():
    if len(sys.argv) != 3:
        print("Usage: ./bench.py [Port] [OPUS/NR-OT]")
        return -1

    IP = "127.0.0.1"
    Port = sys.argv[1]
    nroprf = sys.argv[2] == "NR-OT"
    num_iterations = 1
    freq = 3.2*10**9

    server = "opaque-server-nroprf" if nroprf else "opaque-server"
    with open("bench/"+str(server), "a")  as server_output:
        pq_p_server = subprocess.Popen(["pq-opaque/" +server, str(int(Port) +
            1)], stdout=server_output)

    for _ in range(num_iterations):
        username = "".join(random.choice(string.ascii_lowercase) for _ in range(random.randint(1, 20))) 
        password = "".join(random.choice(string.ascii_lowercase) for _ in range(random.randint(1, 40)))

        print("Bench pq-opaque it: {}".format(_))
        ret = bench(pq_p_server, "pq-opaque/", username, password, IP, str(int(Port) + 1), 60, nroprf=nroprf, pq=True)
        ret = bench2(pq_p_server, "pq-opaque/", username, password, IP, str(int(Port) + 1), 60, nroprf=nroprf, pq=True)
    pq_p_server.kill()

if __name__ == "__main__":
    main()
