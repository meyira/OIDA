# OPRFs from Isogenies: Designs and Analysis

Auxilary files and code for the paper [OPRFs from Isogenies: Designs and Analysis](ia.cr/2023/639), by 
Lena Heimberger, Tobias Hennerbichler, Fredrik Meisingseth, Sebastian Ramacher and Christian Rechberger. 

*NOTE:* This is academic research code and not production-ready. The implementation is not constant-time and may have other errors. 

## Content
The _ code/ _ folder contains the following implementations: 
- _mobile\_psi\_cpp_ optimizes the ECNR implementation from the droidCrypto PSI protocol
- _nr\_ot_ implements the NR-OT stand-alone and with Private Set Intersection
- _opaque_  contains a copy of the libopaque library using isogeny-based primitives
- _opus_ implements OPUS stand-alone
- _opus-psi_ implements OPUS with Private Set Intersection

## Compilation
While `make` compiles all four variants below, we briefly give an overview of the produced binaries. 
 - To compile `opus.c`, please run `make opus`. 
 - To compile `prf.c` which was used  for Figure 4, run `make prf`, which will generate a file noopt.csv with the respective data. 
 - To compile `updatable.c` for Figure 5, run `make updatable` to generate `updatable.csv`. 
 - To compile the client/server binaries used for Figure 10, use `make
   networked` .
Note this was tested on several Linux machines using `gcc`. We link with  `-pthread`, other platforms or compilers may need `-lphtread` instead. 

In addition, we provide the file `leak_OPRF_key_csidh.py`, which estimates how
many random iterations are necessary to recover the key for the NR-OT
OPRF if CSI-FiSh is not used. 
## Ressources
[CSIDH Reference implementation](https://yx7.cc/code/csidh/csidh-latest.tar.xz)
[CSI-FiSh](https://github.com/KULeuven-COSIC/CSI-FiSh)
[droidCrypto](https://github.com/contact-discovery/mobile_psi_cpp/)
[libopaque](https://github.com/stef/libopaque)



