# OPRFs from Isogenies: Designs and Analysis

Lena Heimberger, Fredrik Meisingseth and Christian Rechberger. 

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


