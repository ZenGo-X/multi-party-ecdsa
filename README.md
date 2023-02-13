# Implementing BS21

For more information on the article, see the general [README](../../README.md).

## Organisation of the project

### Original implementation

This repository is a first implementation of the protocol proposed in Bouez & Singh (CT-RSA 2023).<br>
It is based on an implementation by [ZenGo](https://github.com/ZenGo-X/multi-party-ecdsa) of Genaro & Goldfeder 2020.<br>
The original README can be found in [ZENGO_README.md](./ZENGO_README.md). 

The commit used for this implementation is 'a072793725f279f467d0e9f81480afc27cf5f17a'.<br>
All original files remain largely untouched, this implementation should be seen as an added functionality.

### Requirements

The project requires Rust and Nightly. These can be added as follows (linux):
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
snap install rustup
rustup toolchain install nightly
```

Working rustc version: *rustc 1.53.0-nightly (42816d61e 2021-04-24)*.

Some other dependencies are needed:
```
sudo apt-get install libgmp3-dev build-essential
```

Alternatively, you can use docker:
```
docker build --target builder -t tsig .
docker run -it --rm tsig bash
```

### Building and lauching the project

This project was fitted with a Makefile for easier building, cleaning, launching.<br>
The list of available make commands is as follows: 
 * 'make': builds the entire project.
 * BS21 (requires a call to 'make' first)
    - 'make run'       : runs all the steps in succession.
    - 'make keygen'    : runs key generation simulation for BS21. Keygen file is saved in bin/bs21.
    - 'make presign'   : runs presign simulation for BS21. Presignature file is saved in bin/bs21.
    - 'make sign'      : signs locally for BS21. Message is stored as bin/message, local signature is saved in bin/bs21.
    - 'make compile'   : compiles local signatures into a signature & verifies its validity. Signature is saved as bin/signature.
 * GG20 (requires a call to 'make' first)
    - 'make run20'     : runs all the steps in succession.
    - 'make keygen20'  : runs key generation simulation for GG20. Keygen file is saved in bin/gg20.
    - 'make presign20' : runs presign simulation for GG20. Presignature file is saved in bin/gg20.
    - 'make sign20'    : signs locally for GG20. Message is stored as bin/message, local signature is saved in bin/gg20.
    - 'make compile20' : compiles local signatures into a signature & verifies its validity. Signature is saved as bin/signature.

 ## Contributors

 * Main contributor(s): Alexandre Bouez
 * Others of note: Kalpana Singh, Nicolat Heulot, Vincent Herbert