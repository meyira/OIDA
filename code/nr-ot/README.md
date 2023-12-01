# csidh-nr-ot
additional sources from 
* [PQ-OT](https://github.com/encryptogroup/PQ-MPC) for FHE-based OT
* [CSI-FiSh](https://github.com/KULeuven-COSIC/CSI-FiSh) by KU Leuven

## Build Instructions
`mkdir build && cd build && cmake .. && make`


## Execution Instructions
There are two files in test/ : 
* oprf\_server.cpp , requires a port
* oprf\_client.cpp , requires a (local) IP and a port
* psi\_server.cpp , requires a port and a set size (as log2)
* psi\_client.cpp , requires a (local) IP and a port and a set size (as log2)

To execute, run e.g.
`test/oprf_server 12345`
`test/oprf_client 127.0.0.1 12345`

The binaries will both compute on a known input to ensure correctness. 
Note: The OPRF computation sometimes does not give the same result as the PRF
computation. This is due to the Babai reduction. 
