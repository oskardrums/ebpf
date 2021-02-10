ebpf
=====
![Erlang CI](https://github.com/oskardrums/ebpf/workflows/.github/workflows/erlang.yml/badge.svg)

Erlang eBPF library

Status
------

`ebpf` facilitates basic interaction with the Linux eBPF system from Erlang.
Two modules are currently included:
* `ebpf_lib` contains NIFs that wrap Linux native API to eBPF, ultimately calling the `bpf(2)` syscall
* `ebpf_gen` contains functions that generate eBPF instructions according to different parameters

Build
-----

    $ rebar3 compile
    
Test
----
    $ rebar3 do ct, proper

Usage
-----
```erlang
{ok, ProgFd} = ebpf_lib:load(socket_filter,
                             ebpf_lib:assemble([
                                 ebpf_gen:mov64_imm(0,0), % R0 = 0
                                 ebpf_gen:exit_insn()     % return R0
                             ])),
{ok, S} = socket:open(inet, stream, {raw, 0}),
{ok, SockFd} = socket:getopt(S, otp, fd),
ok = ebpf_lib:attach_socket_filter(SockFd, ProgFd).
```
