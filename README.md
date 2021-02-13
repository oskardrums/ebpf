ebpf
=====
![Erlang CI](https://github.com/oskardrums/ebpf/workflows/Erlang%20CI/badge.svg)

Erlang eBPF library

Overview
--------
`ebpf` facilitates basic interaction with the Linux eBPF system from Erlang.
Two modules are currently included:
* `ebpf_user` contains NIFs that wrap the Linux native API to eBPF, ultimately calling the `bpf(2)` syscall
* `ebpf_kern` contains functions that generate eBPF instructions according to different parameters

Status
------
This library is not yet feature complete nor is it extensively tested.

The current API should remain pretty stable, while it is planned to be expanded to expose more eBPF functionalities and perhaps also include a higher lever interface a la `gen_bpf`.

Documentation
-------------

	$ rebar3 edoc

The documentation for the latest version can be browsed at https://oskardrums.github.io/ebpf/

Build
-----

    $ rebar3 compile
    
Test
----

    $ rebar3 do ct, proper

Usage
-----
Checkout the [examples](examples/).

A minimal example is given below:
```erlang
{ok, ProgFd} = ebpf_user:load(socket_filter,
                             ebpf_kern:assemble([
                                 ebpf_kern:mov64_imm(0,0), % R0 = 0
                                 ebpf_kern:exit_insn()     % return R0
                             ])),
{ok, S} = socket:open(inet, stream, {raw, 0}),
{ok, SockFd} = socket:getopt(S, otp, fd),
ok = ebpf_user:attach_socket_filter(SockFd, ProgFd).
```

Contributions
------------
Are welcome :)
Fill free to open an issue or a PR if you encounter any problem or have an idea for an improvement.
