ebpf
=====

Erlang eBPF library

Build
-----

    $ rebar3 compile

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
