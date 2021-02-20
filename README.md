ebpf
=====
![Erlang CI](https://github.com/oskardrums/ebpf/workflows/Erlang%20CI/badge.svg)

Erlang eBPF library

Overview
--------
`ebpf` facilitates basic interaction with the Linux eBPF system from Erlang.
Three modules are currently included:
* `ebpf_user` contains NIFs that wrap the Linux native API to eBPF, ultimately calling the `bpf(2)` syscall
* `ebpf_kern` contains functions that generate eBPF instructions according to different parameters
* `ebpf_asm` contains eBPF assembly and disassembly routines

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
BinProg = ebpf_asm:assemble([
                % Drop all packets
                ebpf_kern:mov64_imm(0, 0), % r0 = 0
                ebpf_kern:exit_insn()      % return r0
            ]),

{ok, FilterProg} = ebpf_user:load(socket_filter, BinProg),
{ok, Sock} = socket:open(inet, stream, {raw, 0}),
ok = ebpf_user:attach_socket_filter(Sock, FilterProg), % All new input to Sock is
ok = ebpf_user:detach_socket_filter(Sock), % Sock is back to normal and FilterProg can be
ok = ebpf_user:close(FilterProg), % FilterProg is unloaded from the kernel

{ok, XdpProg} = ebpf_user:load(xdp, BinProg),
ok = ebpf_user:attach_xdp("lo", XdpProg), % Try pinging 127.0.0.1, go ahead
ok = ebpf_user:detach_xdp("lo"), % Now, that's better :)
ok = ebpf_user:close(XdpProg).
```

For projects that build with `rebar3`, add `ebpf` as a dependency in `rebar.config`:

```erlang
{deps, [{ebpf, {git, "https://github.com/oskardrums/ebpf.git", "main"}}]}.
```

Contributions
------------
Are welcome :)

Fill free to open an issue or a PR if you encounter any problem or have an idea for an improvement.
