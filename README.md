# RRCS
RRCS is a bandwidth-efficient scheme for mitigating the side channel attack in cloud storage services.

# The RRCS paper

Pengfei Zuo, Yu Hua, Cong Wang, Wen Xia, Shunde Cao, and Yuanyuan Sun, "A Bandwidth-efficient Scheme for Mitigating the Side Channel Attack in Cloud Storage Services", submitted to ICDCS 2017.

# Environment

Linux 64bit

# Implementation

We revise the code of [Destor](https://github.com/fomy/destor) to implement a deduplication-based cloud storage system with the client and server via adding two files, i.e., `client.c` and `server.c`. 

The client sends the fingerprints and the data to the server, which is implemented in `client.c` using the interfaces of hash and chunking functions in Destor.

The server detects the redundancy and stores the unique data, which is implemented in `server.c` using the interfaces of fingerprint index and container-based storage functions in Destor.

The Randomized Redundant Chunk (RRC) Algorithm is implemented in `rrcs.c`.  

The flag-based deduplication communication protocol described in the RRCS paper is implemented in `client.c` and `server.c`.