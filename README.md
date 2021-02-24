ebpf
=====
![Erlang CI](https://github.com/oskardrums/ebpf/workflows/Erlang%20CI/badge.svg)

Erlang eBPF library

Overview
--------
`ebpf` is an Erlang library for creating and interacting with eBPF programs.
The following modules are currently included:
* `ebpf_user`: load eBPF programs and use loaded programs
* `ebpf_kern`: generate eBPF instructions according to different parameters
* `ebpf_asm`: eBPF assembly and disassembly routines
* `ebpf_maps`: userspace API to eBPF maps, mimics the Erlang/OTP `maps` interface with eBPF maps

Documentation
-------------

    $ rebar3 edoc

The documentation for the latest release can be browsed on [hexdocs](https://hexdocs.pm/ebpf/).
Documentation for the `main` branch is also available [here](https://oskardrums.github.io/ebpf/).

Usage
-----
Checkout the [examples](examples/).

A minimal example is given below:
```erlang
BinProg = ebpf_asm:assemble([
                % Drop all packets
                ebpf_kern:mov64_imm(r0, 0), % r0 = 0
                ebpf_kern:exit_insn()       % return r0
            ]),

{ok, FilterProg} = ebpf_user:load(socket_filter, BinProg),
{ok, Sock} = socket:open(inet, stream, {raw, 0}),
ok = ebpf_user:attach(Sock, FilterProg), % All new input to Sock is dropped
ok = ebpf_user:detach_socket_filter(Sock), % Sock is back to normal and FilterProg can be
ok = ebpf_user:close(FilterProg), % FilterProg is unloaded from the kernel

{ok, XdpProg} = ebpf_user:load(xdp, BinProg),
ok = ebpf_user:attach("lo", XdpProg), % Try pinging 127.0.0.1, go ahead
ok = ebpf_user:detach_xdp("lo"), % Now, that's better :)
ok = ebpf_user:close(XdpProg).
```

For projects that build with `rebar3`, add `ebpf` as a dependency in `rebar.config`:

```erlang
% From hex
{deps, [ebpf]}.
% Or from github
{deps, [{ebpf, {git, "https://github.com/oskardrums/ebpf.git", "main"}}]}.
```

Build
-----

    $ rebar3 compile

Test
----

    $ rebar3 do ct, proper


Contributions
------------
Are welcome :)

Feel free to open an issue or a PR if you encounter any problem or have an idea for an improvement.
