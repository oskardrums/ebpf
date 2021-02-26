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

The documentation for the latest release can be browsed on [hexdocs](https://hexdocs.pm/ebpf/).
Documentation for the `main` branch is also available [here](https://oskardrums.github.io/ebpf/).
`ebpf` is documented with [edoc](http://erlang.org/doc/apps/edoc/chapter.html), the docs can be
built locally with

    $ rebar3 edoc

Usage
-----
Checkout the [examples](examples/).

A minimal example is given below:
```erlang
% Drop all packets
BinProg = ebpf_asm:assemble(ebpf_kern:return(0)),

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

Add `ebpf` as a dependency in `rebar.config`:

```erlang
% From hex
{deps, [ebpf]}.
% Or from github
{deps, [{ebpf, {git, "https://github.com/oskardrums/ebpf.git", "main"}}]}.
```

{error, eperm}
--------------

Most BPF operations require elevated permissions on most Linux systems.
Lack of permissions usually manifests in `ebpf` in function calls failing with
`{error, eperm}`.

To allow `ebpf` to run privileged operations, BEAM needs to be given permission to do so.
The quickest way to do that for local testing is to run your program as super user, e.g.

	$ sudo `which rebar3` shell

For production systems, Linux capabilities should be given to the user or to the BEAM executable.
Most `bpf(2)` operations demand `CAP_SYS_ADMIN` capability, and some XDP operations
demand `CAP_NET_ADMIN`.

Since Linux 4.4, `socket_filter` type eBPF programs can be loaded without elevated permissions
under some conditions. For more information see [the `bpf(2)` man page](https://man7.org/linux/man-pages/man2/bpf.2.html#NOTES).

Build
-----

    $ rebar3 compile

`ebpf` uses NIFs to communicate with the Linux kernel eBPF system.
You will need `make`, a C compiler and Linux headers for `rebar3` to build
the `.so` that contains those NIFs.


Test
----

    $ rebar3 do ct, proper


Contributions
------------
Are welcome :)

Feel free to open an issue or a PR if you encounter any problem or have an idea for an improvement.
