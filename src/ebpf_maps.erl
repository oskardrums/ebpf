%%%-------------------------------------------------------------------
%%% @author moskar <moskar.drummer@gmail.com>
%%% @copyright (C) 2021, moskar
%%% @doc
%%% @end
%%% Created :  7 Feb 2021 by user <moskar.drummer@gmail.home>
%%%-------------------------------------------------------------------
-module(ebpf_maps).

%% API
-export([
    new/4,
    new/5,
    get/2,
    get/3,
    put/3,
    remove/2,
    close/1,
    fd/1
]).

-type type() ::
    'unspec'
    | 'hash'
    | 'array'
    | 'prog_array'
    | 'perf_event_array'
    | 'percpu_hash'
    | 'percpu_array'
    | 'stack_trace'
    | 'cgroup_array'
    | 'lru_hash'
    | 'lru_percpu_hash'
    | 'lpm_trie'
    | 'array_of_maps'
    | 'hash_of_maps'
    | 'devmap'
    | 'sockmap'
    | 'cpumap'
    | 'xskmap'
    | 'sockhash'
    | 'cgroup_storage'
    | 'reuseport_sockarray'
    | 'percpu_cgroup_storage'
    | 'queue'
    | 'stack'
    | 'sk_storage'
    | 'devmap_hash'
    | 'struct_ops'
    | 'ringbuf'
    | 'inode_storage'
    | 'task_storage'.
%% An `atom' used to specify the type of an eBPF map, see {@link create_map/4}

-type map_option() ::
    'no_prealloc'
    | 'read'
    | 'write'
    | 'zero_seed'
    | 'prog_read'
    | 'prog_write'
    | 'clone'
    | 'mmapable'.

-record(bpf_map, {
    type = unspec :: type(),
    fd = -1 :: integer(),
    key_size = 0 :: non_neg_integer(),
    value_size = 0 :: non_neg_integer(),
    max_entries = 0 :: non_neg_integer()
}).
-type key() :: binary() | integer().
-type value() :: binary().
-opaque ebpf_map() :: #bpf_map{}.
%% An active eBPF map as returned by {@link new/5}.

-export_type([ebpf_map/0]).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Returns a new empty eBPF map.
%%
%% If successful, the returned map can be used from userspace via the
%% functions in this module, as well as shared with eBPF programs e.g.
%% via {@link ebpf_kern:ld_map_fd/2}.
%%
%% `KeySize' and `ValueSize' are given in octets.
%%
%% The following `Options' are currently supported:
%%
%% `no_prealloc' - The kernel will not allocate the needed memory for
%% the map ahead of time.
%% Defaults to `false', i.e. the map is preallocated.
%%
%% `read' - Limits userspace access to the map to read-only.
%% Defaults to `false'.
%%
%% `write' - Limits userspace access to the map to write-only.
%% Defaults to `false'.
%%
%% `zero_seed' - Initializes the map's hash function with a null seed,
%% Which can be useful for testing.
%% This option should not be used in production.
%% Defaults to `false'.
%%
%% `prog_read' - Limits the access to the map from eBPF programs to
%% read-only.
%% Defaults to `false'.
%%
%% `prog_write' - Limits the access to the map from eBPF programs to
%% write-only.
%% Defaults to `false'.
%%
%% @end
%%--------------------------------------------------------------------
-spec new(
    Type :: type(),
    KeySize :: integer(),
    ValueSize :: integer(),
    MaxEntries :: integer(),
    Options :: [map_option()]
) -> ebpf_map() | {'error', atom()}.
new(Type, KeySize, ValueSize, MaxEntries, Options) ->
    Flags = read_map_options(Options),
    case
        ebpf_lib:bpf_create_map(
            type_to_int(Type),
            KeySize,
            ValueSize,
            MaxEntries,
            Flags
        )
    of
        {ok, Fd} ->
            #bpf_map{
                fd = Fd,
                key_size = KeySize,
                value_size = ValueSize,
                max_entries = MaxEntries
            };
        {error, Reason} ->
            {error, Reason}
    end.

%%--------------------------------------------------------------------
%% @doc
%% Same as {@link new/5}, with default options.
%% @end
%%--------------------------------------------------------------------
-spec new(
    Type :: type(),
    KeySize :: integer(),
    ValueSize :: integer(),
    MaxEntries :: integer()
) -> ebpf_map() | {'error', atom()}.

new(Type, KeySize, ValueSize, MaxEntries) ->
    new(Type, KeySize, ValueSize, MaxEntries, []).

%%--------------------------------------------------------------------
%% @doc
%% Returns the value associated with `Key' in eBPF map `Map' if `Map'
%% contains `Key'.
%%
%% See also [http://erlang.org/doc/man/maps.html#get-2].
%% @end
%%--------------------------------------------------------------------
-spec get(key(), ebpf_map()) -> value().
get(
    Key,
    #bpf_map{
        fd = Fd,
        key_size = KeySize,
        value_size = ValueSize
    } = _Map
) when is_binary(Key), byte_size(Key) == KeySize ->
    case
        ebpf_lib:bpf_lookup_map_element(
            Fd,
            to_binary(Key, KeySize),
            ValueSize,
            0
        )
    of
        {ok, Value} -> Value;
        {error, enoent} -> throw({badkey, Key})
    end.

%%--------------------------------------------------------------------
%% @doc
%% Returns the value associated with `Key' in eBPF map `Map' if `Map'
%% contains `Key', otherwise returns `Default'.
%% @end
%%--------------------------------------------------------------------
-spec get(key(), ebpf_map(), value()) -> value().
get(
    Key,
    #bpf_map{
        fd = Fd,
        key_size = KeySize,
        value_size = ValueSize
    },
    Default
) when byte_size(Key) == KeySize ->
    case
        ebpf_lib:bpf_lookup_map_element(
            Fd,
            Key,
            ValueSize,
            0
        )
    of
        {ok, Value} -> Value;
        {error, enoent} -> Default
    end.

%%--------------------------------------------------------------------
%% @doc
%% Returns the value associated with `Key' in eBPF map `Map' if `Map'
%% contains `Key', otherwise returns `Default'.
%%
%% See also [http://erlang.org/doc/man/maps.html#put-3].
%% @end
%%--------------------------------------------------------------------
-spec put(key(), value(), ebpf_map()) -> ebpf_map().
put(
    Key,
    Value,
    #bpf_map{
        fd = Fd,
        key_size = KeySize,
        value_size = ValueSize
    } = Map
) when byte_size(Value) == ValueSize ->
    ok = ebpf_lib:bpf_update_map_element(Fd, to_binary(Key, KeySize), Value, 0),
    Map.

%%--------------------------------------------------------------------
%% @doc
%% Removes the `Key', if it exists, and its associated value from `Map1'
%% and returns a new map `Map2' without key `Key'.
%%
%% See also [http://erlang.org/doc/man/maps.html#remove-2].
%% @end
%%--------------------------------------------------------------------
-spec remove(key(), ebpf_map()) -> ebpf_map().
remove(Key, #bpf_map{fd = Fd, key_size = KeySize} = Map1) ->
    case ebpf_lib:bpf_delete_map_element(Fd, to_binary(Key, KeySize)) of
        ok -> Map1;
        {error, enoent} -> Map1;
        {error, Other} -> {error, Other}
    end.

%%--------------------------------------------------------------------
%% @doc
%% Closes `Map'.
%% @end
%%--------------------------------------------------------------------
-spec close(Map :: ebpf_map()) -> 'ok' | {'error', atom()}.
close(Map) ->
    ebpf_lib:bpf_close(Map#bpf_map.fd).

%%--------------------------------------------------------------------
%% @doc
%% Returns a File Descriptor for `Map'.
%%
%% Can be used for passing a map to eBPF programs, e.g. via {@link ebpf_kern:ld_map_fd/2}.
%% @end
%%--------------------------------------------------------------------
-spec fd(ebpf_map()) -> non_neg_integer().
fd(Map) -> Map#bpf_map.fd.

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec read_map_options([map_option()]) -> non_neg_integer().
read_map_options(Options) ->
    read_map_options(Options, 0).

-spec read_map_options([map_option()], non_neg_integer()) -> non_neg_integer().
read_map_options([no_prealloc | More], Flags0) ->
    read_map_options(More, Flags0 bor (1 bsl 0));
read_map_options([read | More], Flags0) ->
    read_map_options(More, Flags0 bor (1 bsl 3));
read_map_options([write | More], Flags0) ->
    read_map_options(More, Flags0 bor (1 bsl 4));
read_map_options([zero_seed | More], Flags0) ->
    read_map_options(More, Flags0 bor (1 bsl 6));
read_map_options([prog_read | More], Flags0) ->
    read_map_options(More, Flags0 bor (1 bsl 7));
read_map_options([prog_write | More], Flags0) ->
    read_map_options(More, Flags0 bor (1 bsl 8));
read_map_options([clone | More], Flags0) ->
    read_map_options(More, Flags0 bor (1 bsl 9));
read_map_options([mmapable | More], Flags0) ->
    read_map_options(More, Flags0 bor (1 bsl 10));
read_map_options([], Flags) ->
    Flags.

-spec to_binary(key(), non_neg_integer()) -> binary().
to_binary(Bin, Size) when is_binary(Bin), byte_size(Bin) == Size ->
    Bin;
to_binary(Int, Size) when is_integer(Int) ->
    <<Int:(Size * 8)>>.

-spec type_to_int(type()) -> integer().
type_to_int(unspec) -> 0;
type_to_int(hash) -> 1;
type_to_int(array) -> 2;
type_to_int(prog_array) -> 3;
type_to_int(perf_event_array) -> 4;
type_to_int(percpu_hash) -> 5;
type_to_int(percpu_array) -> 6;
type_to_int(stack_trace) -> 7;
type_to_int(cgroup_array) -> 8;
type_to_int(lru_hash) -> 9;
type_to_int(lru_percpu_hash) -> 10;
type_to_int(lpm_trie) -> 11;
type_to_int(array_of_maps) -> 12;
type_to_int(hash_of_maps) -> 13;
type_to_int(devmap) -> 14;
type_to_int(sockmap) -> 15;
type_to_int(cpumap) -> 16;
type_to_int(xskmap) -> 17;
type_to_int(sockhash) -> 18;
type_to_int(cgroup_storage) -> 19;
type_to_int(reuseport_sockarray) -> 20;
type_to_int(percpu_cgroup_storage) -> 21;
type_to_int(queue) -> 22;
type_to_int(stack) -> 23;
type_to_int(sk_storage) -> 24;
type_to_int(devmap_hash) -> 25;
type_to_int(struct_ops) -> 26;
type_to_int(ringbuf) -> 27;
type_to_int(inode_storage) -> 28;
type_to_int(task_storage) -> 29.
