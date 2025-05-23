[![AppVeyor](https://ci.appveyor.com/api/projects/status/mjujhh01coab3fsw/branch/OQS-OpenSSL_1_1_1-stable?svg=true)](https://ci.appveyor.com/project/dstebila/openssl/branch/OQS-OpenSSL_1_1_1-stable), [![CircleCI](https://circleci.com/gh/open-quantum-safe/openssl/tree/OQS-OpenSSL_1_1_1-stable.svg?style=svg)](https://circleci.com/gh/open-quantum-safe/openssl/tree/OQS-OpenSSL_1_1_1-stable)

OQS-OpenSSL\_1\_1\_1
==================================

[OpenSSL](https://openssl.org/) is an open-source implementation of the TLS protocol and various cryptographic algorithms ([View the original README](https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/README).)

OQS-OpenSSL\_1\_1\_1 is a fork of OpenSSL 1.1.1 that adds quantum-safe key exchange and authentication algorithms using [liboqs](https://github.com/open-quantum-safe/liboqs) for prototyping and evaluation purposes. This fork is not endorsed by the OpenSSL project.

- [Overview](#overview)
- [Status](#status)
  * [Limitations and Security](#limitations-and-security)
  * [Supported Algorithms](#supported-algorithms)
- [Quickstart](#quickstart)
  * [Building](#building)
    * [Linux and macOS](#linux-and-macOS)
    * [Windows](#windows)
    * [Build Options](#build-options)
  * [Running](#running)
    * [TLS demo](#tls-demo)
    * [CMS demo](#cms-demo)
    * [Performance testing](#performance-testing)
    * [Integration testing](#integration-testing)
- [Third Party Integrations](#third-party-integrations)
- [Contributing](#contributing)
- [License](#license)
- [Team](#team)
- [Acknowledgements](#acknowledgements)

## Overview

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms. See [here](https://github.com/open-quantum-safe/liboqs/) for more information.

**OQS-OpenSSL\_1\_1\_1-stable** is a fork that integrates liboqs into OpenSSL 1.1.1.  The goal of this integration is to provide easy prototyping of quantum-safe cryptography in the TLS 1.3 protocol.

Both liboqs and this fork are part of the **Open Quantum Safe (OQS) project**, which aims to develop and prototype quantum-safe cryptography (QSC). More information about the project can be found [here](https://openquantumsafe.org/).

Note that, referencing the terminology defined by [ETSI](https://www.etsi.org/technologies/quantum-safe-cryptography) and [CSA](https://downloads.cloudsecurityalliance.org/assets/research/quantum-safe-security/applied-quantum-safe-security.pdf), the terms "post-quantum cryptography" (PQC), "quantum-safe cryptography" (QSC) and "quantum-resistant cryptography" (QRC) all refer to the same class of cryptographic algorithms that is made available for use via this fork.

## Status

This fork is currently in sync with the [OpenSSL\_1\_1\_1u tag](https://github.com/openssl/openssl/tree/OpenSSL_1_1_1u), and adds the following:

- quantum-safe key exchange in TLS 1.3
- hybrid (quantum-safe + elliptic curve) key exchange in TLS 1.3
- quantum-safe authentication in TLS 1.3
- hybrid (quantum-safe + RSA/elliptic curve) authentication in TLS 1.3
- CMS support (sign and verify using any of the [supported quantum-safe signature algorithms](#authentication))

For more information, see the [release notes](RELEASE.md).

**WE DO NOT RECOMMEND RELYING ON THIS FORK IN A PRODUCTION ENVIRONMENT OR TO PROTECT ANY SENSITIVE DATA.** This fork is at an experimental stage, and has not received the same level of auditing and analysis that OpenSSL has received. See the [Limitations and Security](#limitations-and-security) section below for more information.

liboqs and our integration into OpenSSL is provided "as is", without warranty of any kind.  See the [LICENSE](https://github.com/open-quantum-safe/liboqs/blob/main/LICENSE.txt) for the full disclaimer.

### Limitations and security

As research advances, the supported algorithms may see rapid changes in their security, and may even prove insecure against both classical and quantum computers.

We believe that the NIST Post-Quantum Cryptography standardization project is currently the best avenue to identifying potentially quantum-resistant algorithms, and strongly recommend that applications and protocols rely on the outcomes of the NIST standardization project when deploying quantum-safe cryptography.

While at the time of this writing there are no vulnerabilities known in any of the quantum-safe algorithms used in this fork, it is advisable to wait on deploying quantum-safe algorithms until further guidance is provided by the standards community, especially from the NIST standardization project.

We realize some parties may want to deploy quantum-safe cryptography prior to the conclusion of the standardization project.  We strongly recommend such attempts make use of so-called **hybrid cryptography**, in which quantum-safe public-key algorithms are combined with traditional public key algorithms (like RSA or elliptic curves) such that the solution is at least no less secure than existing traditional cryptography. This fork provides the ability to use hybrid cryptography.

Proofs of TLS such as [[JKSS12]](https://eprint.iacr.org/2011/219) and [[KPW13]](https://eprint.iacr.org/2013/339) require a key exchange mechanism that has a form of active security, either in the form of the PRF-ODH assumption, or an IND-CCA KEM.
Some of the KEMs provided in liboqs do provide IND-CCA security; others do not ([these datasheets](https://github.com/open-quantum-safe/liboqs/tree/main/docs/algorithms) specify which provide what security), in which case existing proofs of security of TLS against active attackers do not apply.

### Supported Algorithms

If an algorithm is provided by liboqs but is not listed below, it might still be possible to use it in the fork through [either one of two ways](https://github.com/open-quantum-safe/openssl/wiki/Using-liboqs-algorithms-not-in-the-fork).

#### Key Exchange

The following quantum-safe algorithms from liboqs are supported (assuming they have been enabled in liboqs):

<!--- OQS_TEMPLATE_FRAGMENT_LIST_KEXS_START -->
- **BIKE**: `bikel1`, `bikel3`, `bikel5`
- **CRYSTALS-Kyber**: `kyber512`, `kyber768`, `kyber1024`
- **FrodoKEM**: `frodo640aes`, `frodo640shake`, `frodo976aes`, `frodo976shake`, `frodo1344aes`, `frodo1344shake`
- **HQC**: `hqc128`, `hqc192`, `hqc256`†
<!--- OQS_TEMPLATE_FRAGMENT_LIST_KEXS_END -->

If ``<KEX>`` is any of the algorithms listed above, the following hybrid algorithms are supported:

- if `<KEX>` claims NIST L1 or L2 security, the fork provides the method `p256_<KEX>`, which combine `<KEX>` with ECDH using the P256 curve.
- if `<KEX>` claims NIST L3 or L4 security, the fork provides the method `p384_<KEX>`, which combines `<KEX>` with ECDH using the P384 curve.
- if `<KEX>` claims NIST L5 security, the fork provides the method `p521_<KEX>`, which combines `<KEX>` with ECDH using the P521 curve.

For example, since `kyber768` [claims NIST L3 security](https://github.com/open-quantum-safe/liboqs/blob/main/docs/algorithms/kem/kyber.md), the hybrid `p384_kyber768` is available.

Note that algorithms marked with a dagger (†) have large stack usage and may cause failures when run on threads or in constrained environments. For further information about each algorithm's strengths and limitations, see the [documentation markdown files at liboqs](https://github.com/open-quantum-safe/liboqs/tree/main/docs/algorithms/kem).

#### Authentication

The following digital signature algorithms from liboqs are supported by the fork. **Note that not all variants of all algorithms are enabled by default; algorithms that are enabled by default are marked with an asterisk, and should you wish to enable additional variants, consult [the "Code Generation" section of the documentation in the wiki](https://github.com/open-quantum-safe/openssl/wiki/Using-liboqs-algorithms-not-in-the-fork#code-generation)**.

<!--- OQS_TEMPLATE_FRAGMENT_LIST_SIGS_START -->
- **CRYSTALS-Dilithium**:`dilithium2`\*, `dilithium3`\*, `dilithium5`\*
- **Falcon**:`falcon512`\*, `falcon1024`\*
- **SPHINCS-SHA2**:`sphincssha2128fsimple`\*, `sphincssha2128ssimple`\*, `sphincssha2192fsimple`\*, `sphincssha2192ssimple`, `sphincssha2256fsimple`, `sphincssha2256ssimple`
- **SPHINCS-SHAKE**:`sphincsshake128fsimple`\*, `sphincsshake128ssimple`, `sphincsshake192fsimple`, `sphincsshake192ssimple`, `sphincsshake256fsimple`, `sphincsshake256ssimple`
<!--- OQS_TEMPLATE_FRAGMENT_LIST_SIGS_END -->

The following hybrid algorithms are supported; they combine a quantum-safe algorithm listed above with a traditional digital signature algorithm (`<SIG>` is any one of the algorithms listed above):

- if `<SIG>` claims NIST L1 or L2 security, then the fork provides the methods `rsa3072_<SIG>` and `p256_<SIG>`, which combine `<SIG>` with RSA3072 and with ECDSA using NIST's P256 curve respectively.
- if `<SIG>` claims NIST L3 or L4 security, the fork provides the method `p384_<SIG>`, which combines `<SIG>` with ECDSA using NIST's P384 curve.
- if `<SIG>` claims NIST L5 security, the fork provides the method `p521_<SIG>`, which combines `<SIG>` with ECDSA using NIST's P521 curve.

For example, since `dilithium2` [claims NIST L2 security](https://github.com/open-quantum-safe/liboqs/blob/main/docs/algorithms/sig/dilithium.md), the hybrids `rsa3072_dilithium2` and `p256_dilithium2` are available.

For further information about each algorithm's strengths and limitations, see the [documentation markdown files at liboqs](https://github.com/open-quantum-safe/liboqs/tree/main/docs/algorithms/sig).

## Quickstart

The steps below have been confirmed to work on macOS 10.14 (with clang 10.0.0), Ubuntu 18.04.1 (with gcc-7) and should work on more recent versions of these operating systems/compilers. They have also been confirmed to work on Windows 10 with Visual Studio 2019. All commands below are just examples and might also be used and work differently as per the respective packages' documentations.

### Building

#### Linux and macOS

#### Step 0: Get pre-requisites

On **Ubuntu**, you need to install the following packages:

	sudo apt install cmake gcc libtool libssl-dev make ninja-build git

On **macOS**, you need to install the following packages using `brew` (or a package manager of your choice):

	brew install cmake ninja libtool openssl@1.1

Then, get source code of this fork (`<OPENSSL_DIR>` is a directory of your choosing):

	git clone --branch OQS-OpenSSL_1_1_1-stable https://github.com/open-quantum-safe/openssl.git <OPENSSL_DIR>

#### Step 1: Build and install liboqs

The following instructions will download and build liboqs, then install it into a subdirectory inside the OpenSSL folder.

	git clone --branch main https://github.com/open-quantum-safe/liboqs.git
	cd liboqs
	mkdir build && cd build
	cmake -GNinja -DCMAKE_INSTALL_PREFIX=<OPENSSL_DIR>/oqs ..
	ninja
	ninja install

Building liboqs requires your system to have (a standard) OpenSSL already installed. `configure` will detect it if it is located in a standard location, such as `/usr` or `/usr/local/opt/openssl` (for brew on macOS).  Otherwise, you may need to specify it with `-DOPENSSL_ROOT_DIR=<path-to-system-openssl-dir>` added to the `cmake` command.

*Note*: This will only work correctly, if the OpenSSL version used to build `liboqs` is a version below 3.0.0. If the standard OpenSSL on the build system or the version pointed to by the above `-DOPENSSL_ROOT_DIR=...` command is a version >= 3.0.0, then you _must_ add the option `-DOQS_USE_OPENSSL=OFF` to the above `cmake` build command to successfully complete the subsequent build steps for this package.

#### Step 2: Build the fork

Now we follow the standard instructions for building OpenSSL. Navigate to `<OPENSSL_DIR>`, and:

on **Ubuntu**, run:

	./Configure no-shared linux-x86_64 -lm
	make -j

on **macOS** (x86_64), run:

	./Configure no-shared darwin64-x86_64-cc
	make -j

on **macOS** (M1 / arm64), run:

	./Configure no-shared darwin64-arm64-cc
	make -j

#### Windows

#### Step 0

Make sure you can build the unmodified version of OpenSSL by following the instructions in [INSTALL](https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/INSTALL) and [NOTES.WIN](https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/NOTES.WIN).

Then, get the fork source code (`<OPENSSL_DIR>` is a directory of your choosing):

	git clone --branch OQS-OpenSSL_1_1_1-stable https://github.com/open-quantum-safe/openssl.git <OPENSSL_DIR>

The above command uses `git`, but alternatively, an archive of the source code can be downloaded and expanded into `<OPENSSL_DIR>`

#### Step 1: Build and install liboqs

The following instructions will download (using git, alternatively, [download an archive of the source](https://github.com/open-quantum-safe/liboqs/archive/main.zip) and unzip the project) and build the x64 release configuration of liboqs, then copy the required files it into a subdirectory inside the OpenSSL folder.  You may need to install dependencies before building liboqs; see the [liboqs README](https://github.com/open-quantum-safe/liboqs/blob/main/README.md).

	git clone --branch main https://github.com/open-quantum-safe/liboqs.git
	cd liboqs
	mkdir build
	cd build
	cmake -GNinja -DCMAKE_INSTALL_PREFIX=<OPENSSL_DIR>\oqs ..
	ninja
	ninja install

#### Step 2: Build the fork

Now we follow the standard instructions for building OpenSSL:

	perl Configure VC-WIN64A
	nmake

**N.B.**: The fork can also be built as a set of shared libraries by specifying `shared` instead of `no-shared` in the above commands; We have used `no-shared` to avoid having to get the libraries in the right place for the runtime linker.

#### Build options

##### Default algorithms announced

By default, the fork is built to only announce 128-bit strength QSC hybrid KEM algorithms in the initial TLS handshake (using the EC groups announced extension of TLS1.3). This algorithm set can be changed to an arbitrary collection at build time by setting the variable `OQS_DEFAULT_GROUPS` to a colon-separated list of [KEM algorithms supported](#key-exchange), e.g., by running
```
./Configure no-shared linux-x86_64 -DOQS_DEFAULT_GROUPS=\"p384_kyber768:X25519:newhope1024cca\" -lm
```

*Note*: When executing the SSL test suite via `make test`, be sure to include not only `X25519` but also `ED448` in the algorithm list specified in `OQS_DEFAULT_GROUPS` to ensure classic algorithm tests pass.

The announced algorithms can also be modified at runtime by setting the `-curves` or `-groups` parameter with programs supporting this option (e.g., `openssl s_client` or `openssl s_server`) or by using the `SSL_CTX_set1_groups_list` API call. A final alternative is to set the `TLS_DEFAULT_GROUPS` environment variable to such colon-separated list of [KEM algorithms supported](#key-exchange). This option only works if the `SSL_CTX_set1_groups_list` API call has not been used.

### Running

#### TLS demo

OpenSSL contains a basic TLS server (`s_server`) and TLS client (`s_client`) which can be used to demonstrate and test TLS connections.

To run a server, you first need to generate an X.509 certificate, using either a classical (`rsa`), quantum-safe (any quantum-safe authentication algorithm in the [Supported Algorithms](#supported-algorithms) section above), or hybrid (any hybrid authentication algorithm in the [Supported Algorithms](#supported-algorithms) section above) algorithm. The server certificate can either be self-signed or part of a chain. In either case, you need to generate a self-signed root CA certificate using the following command, replacing `<SIG>` with an algorithm mentioned above:

	apps/openssl req -x509 -new -newkey <SIG> -keyout <SIG>_CA.key -out <SIG>_CA.crt -nodes -subj "/CN=oqstest CA" -days 365 -config apps/openssl.cnf

If you want an ECDSA certificate (`<SIG>` = `ecdsa`), you instead need to run:

	apps/openssl req -x509 -new -newkey ec:<(apps/openssl ecparam -name secp384r1) -keyout <SIG>_CA.key -out <SIG>_CA.crt -nodes -subj "/CN=oqstest" -days 365 -config apps/openssl.cnf

The root CA certificate can be used directly to start the server (see below), or can be used to issue a server certificate, using the usual OpenSSL process (note that for simplicity, we use the same algorithm for the server and CA certificates; in practice the CA is likely to use a stronger one):

1. The server generates its key pair, a certificate request and sends the latter to the CA:

		apps/openssl req -new -newkey <SIG> -keyout <SIG>_srv.key -out <SIG>_srv.csr -nodes -subj "/CN=oqstest server" -config apps/openssl.cnf

2. The CA generates the signed server certificate:

		apps/openssl x509 -req -in <SIG>_srv.csr -out <SIG>_srv.crt -CA <SIG>_CA.crt -CAkey <SIG>_CA.key -CAcreateserial -days 365

Using the key and certificate thus created, running a basic TLS server with all possible key-exchange algorithms enabled, can be achieved using the following command, replacing `<SERVER>` with either `<SIG>_CA` or `<SIG>_srv`:

	apps/openssl s_server -cert <SERVER>.crt -key <SERVER>.key -www -tls1_3

In another terminal window, you can run a TLS client requesting one of the supported key-exchanges (`<KEX>` = one of the quantum-safe or hybrid key exchange algorithms listed in the [Supported Algorithms section above](#key-exchange):

	apps/openssl s_client -groups <KEX> -CAfile <SIG>_CA.crt

#### CMS demo

OpenSSL has facilities to perform signing operations pursuant to [RFC 5652](https://datatracker.ietf.org/doc/rfc5652). This fork can be used to perform such operations with quantum-safe algorithms.

Building on the artifacts created in the TLS setup above (CA and server certificate creation using a specific (quantum-safe) `<SIG>` algorithm), the following command can be used to generate a (quantum-safe) signed file from some input file:

	apps/openssl cms -in inputfile -sign -signer <SIG>_srv.crt -inkey <SIG>_srv.key -nodetach -outform pem -binary -out signedfile.cms 

This command can be used to verify (and extract the contents) of the CMS file resultant from the command above:

	apps/openssl cms -verify -CAfile <SIG>_CA.crt -inform pem -in signedfile.cms -crlfeol -out signeddatafile

The contents of `inputfile` and the resultant `signeddatafile` should be the same.

Also supported are general signing operations using the standard [OpenSSL dgst](https://www.openssl.org/docs/man1.1.1/man1/dgst.html) commands using QSC public/private keys of [any of the supported signature algorithms](#authentication). Example command using the same file notation used above:

        echo TestDataToSign | apps/openssl dgst -sha256 -sign <SIG>_srv.key -out signature

#### Performance testing

##### TLS end-to-end testing

"Empty" TLS handshakes can be performance tested via the standard `openssl s_time` command. In order to suitably trigger this with an OQS KEM/SIG pair of choice, first follow all steps outlined in the [TLS demo](#tls-demo) section to obtain an OQS-algorithm-signed server certificate. You can then run the performance test in one of two ways:

- Start the server with the desired certificate and key exchange algorithm as follows (`<SERVER>` and `<KEX>` are defined in the [TLS demo](#tls-demo) section above):

```
apps/openssl s_server -cert <SERVER>.crt -key <SERVER>.key -www -tls1_3 -groups <KEX>
```

Then run `apps/openssl s_time`

- Start the server with the desired certificate:

```
apps/openssl s_server -cert <SERVER>.crt -key <SERVER>.key -www -tls1_3
```

and specify the key-exchange algorithm through `s_time` using `apps/openssl s_time -curves <KEX>`.

##### Algorithm speed testing

OpenSSL also has facilities to perform pure speed tests of the cryptographic algorithms supported. This can be used to compare the relative performance of OQS algorithms.

To measure the speed of all KEM algorithms supported by the underlying `liboqs`:

	apps/openssl speed oqskem

Similarly, to measure the speed of all OQS signature algorithms:

	apps/openssl speed oqssig

As with standard OpenSSL, one can also pass a particular algorithm name to be tested, e.g., `apps/openssl speed dilithium2`.

We also have [docker-based performance test environments in the `oqs-demos` subproject](https://github.com/open-quantum-safe/oqs-demos/tree/master/curl#performance-testing).

#### Integration testing

We have various `pytest` test suites for the TLS and CMS functionalities. Consult the [oqs-test/ README](https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/oqs-test/README.md) for more information.

## Third Party Integrations

Various third-party software applications, such as [nginx](https://www.nginx.com/) and [curl](https://curl.haxx.se/) use OpenSSL to establish TLS connections; they can be built against our fork to make use of quantum-safe cryptography. The [oqs-demos](https://github.com/open-quantum-safe/oqs-demos) repository provides instructions for building various software like so.

## Contributing

Contributions are gratefully welcomed. See our [Contributing Guide](https://github.com/open-quantum-safe/openssl/wiki/Contributing-Guide) for more details.

## License

All modifications to this repository are released under the same terms as OpenSSL, namely as described in the file [LICENSE](https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/LICENSE).

## Team

The Open Quantum Safe project is led by [Douglas Stebila](https://www.douglas.stebila.ca/research/) and [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) at the University of Waterloo.

Contributors to OQS-OpenSSL\_1\_1\_1 include:

- Christian Paquin (Microsoft Research)
- Dimitris Sikeridis (University of New Mexico / Cisco Systems)
- Douglas Stebila (University of Waterloo)
- Goutam Tamvada (University of Waterloo)
- Michael Baentsch (baentsch.ch)

## Acknowledgments

Financial support for the development of Open Quantum Safe has been provided by Amazon Web Services and the Canadian Centre for Cyber Security.

We'd like to make a special acknowledgement to the companies who have dedicated programmer time to contribute source code to OQS, including Amazon Web Services, evolutionQ, Microsoft Research, Cisco Systems, and IBM Research.

Research projects which developed specific components of OQS have been supported by various research grants, including funding from the Natural Sciences and Engineering Research Council of Canada (NSERC); see [here](https://openquantumsafe.org/papers/SAC-SteMos16.pdf) and [here](https://openquantumsafe.org/papers/NISTPQC-CroPaqSte19.pdf) for funding acknowledgments.
