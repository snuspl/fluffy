FROM ubuntu:18.04

ENV PATH /root/.cargo/bin:$PATH
ENV PATH /usr/local/go/bin:$PATH

ARG DEBIAN_FRONTEND=noninteractive



RUN apt update
RUN apt-get update
RUN apt install -y git wget curl build-essential clang gcc cmake

RUN wget https://golang.org/dl/go1.14.4.linux-amd64.tar.gz
RUN tar -C /usr/local/ -xzf go1.14.4.linux-amd64.tar.gz

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain none -y


RUN rustup toolchain install nightly --allow-downgrade --profile minimal --component clippy

############################ BUILD the repository
COPY . /root/

RUN cd /root/custom-libfuzzer/ && cargo build

ENV GOROOT="/usr/local/go"
ENV GOPATH="/root/geth"

RUN cd /root/geth/src/github.com/ethereum/go-ethereum/ && make all
#RUN cd /root/geth && make all

RUN mkdir /root/fifos


############################ BUILD the fuzzer
RUN cargo install cargo-fuzz
RUN cd /root/openethereum/evmfuzz && cargo fuzz build --dev fuzz_target_1

############################ RUN the fuzzer
RUN cd /root/openethereum/evmfuzz && cargo fuzz run --dev fuzz_target_1

