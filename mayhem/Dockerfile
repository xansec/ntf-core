FROM ubuntu AS builder

RUN apt-get update -y && apt-get install -y git clang llvm cmake ninja-build
RUN mkdir /bde
WORKDIR /bde
RUN git clone https://github.com/bloomberg/bde-tools.git
ENV PATH "$PATH:/bde/bde-tools/bin"
RUN git clone https://github.com/bloomberg/bde.git
WORKDIR /bde/bde
RUN apt-get install -y pkg-config lldb gdb
RUN eval `bbs_build_env -u dbg_64` && bbs_build configure && bbs_build build && bbs_build install

RUN mkdir /bde/ntf-core
WORKDIR /bde/ntf-core
COPY . .
RUN ./configure --prefix /bde/bde/_install/opt/bb --compiler "clang" --with-fuzzers --without-warnings-as-errors 
RUN cmake --build .
