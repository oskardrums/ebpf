%%%-------------------------------------------------------------------
%%% @author moskar <moskar.drummer@gmail.com>
%%% @copyright (C) 2021, moskar
%%% @private
%%%
%%% eBPF NIFs
%%%
%%% @end
%%% Created :  7 Feb 2021 by user <moskar.drummer@gmail.home>
%%%-------------------------------------------------------------------
-module(ebpf_lib).

%% API
-export([
    bpf_load_program/5,
    bpf_attach_socket_filter/2,
    bpf_detach_socket_filter/1,
    bpf_attach_xdp/2,
    bpf_create_map/5,
    bpf_update_map_element/4,
    bpf_lookup_map_element/4,
    bpf_delete_map_element/2,
    bpf_get_map_next_key/2,
    bpf_test_program/4,
    bpf_close/1
]).

-on_load(init/0).

-define(APPNAME, ebpf).
-define(LIBNAME, ?MODULE).

%%%===================================================================
%%% API
%%%===================================================================

-spec bpf_load_program(
    non_neg_integer(),
    binary(),
    non_neg_integer(),
    string(),
    non_neg_integer()
) ->
    {'ok', non_neg_integer()}
    | {'ok', non_neg_integer(), string()}
    | {'error', atom()}
    | {'error', atom(), string()}.
bpf_load_program(_ProgType, _BinProg, _LogBufferSize, _License, _Flags) ->
    not_loaded(?LINE).

-spec bpf_attach_socket_filter(non_neg_integer(), non_neg_integer()) -> 'ok' | {'error', atom()}.
bpf_attach_socket_filter(_SockFd, _ProgFd) ->
    not_loaded(?LINE).

-spec bpf_detach_socket_filter(non_neg_integer()) -> 'ok' | {'error', atom()}.
bpf_detach_socket_filter(_SockFd) ->
    not_loaded(?LINE).

-spec bpf_attach_xdp(non_neg_integer(), integer()) -> 'ok' | {'error', atom()}.
bpf_attach_xdp(_IfIndex, _ProgFd) ->
    not_loaded(?LINE).

-spec bpf_create_map(non_neg_integer(), integer(), integer(), integer(), non_neg_integer()) ->
    {'ok', non_neg_integer()} | {'error', atom()}.
bpf_create_map(_Type, _KeySize, _ValueSize, _MaxEntries, _Flags) ->
    not_loaded(?LINE).

-spec bpf_update_map_element(integer(), binary(), binary(), non_neg_integer()) ->
    'ok' | {'error', atom()}.
bpf_update_map_element(_Map, _Key, _Value, _Flags) ->
    not_loaded(?LINE).

-spec bpf_lookup_map_element(integer(), binary(), non_neg_integer(), non_neg_integer()) ->
    {'ok', binary()} | {'error', atom()}.
bpf_lookup_map_element(_Map, _Key, _ValueSize, _Flags) ->
    not_loaded(?LINE).

-spec bpf_delete_map_element(integer(), binary()) -> 'ok' | {'error', atom()}.
bpf_delete_map_element(_Map, _Key) ->
    not_loaded(?LINE).

-spec bpf_get_map_next_key(integer(), binary()) -> {'ok', binary()} | {'error', atom()}.
bpf_get_map_next_key(_Map, _Key) ->
    not_loaded(?LINE).

-spec bpf_test_program(integer(), integer(), binary(), non_neg_integer()) ->
    {'ok', non_neg_integer(), binary(), non_neg_integer()} | {'error', atom()}.
bpf_test_program(_Prog, _Repeat, _Data, _DataOutSize) ->
    not_loaded(?LINE).

-spec bpf_close(integer()) -> 'ok' | {'error', atom()}.
bpf_close(_Fd) ->
    not_loaded(?LINE).

%%%===================================================================
%%% Internal functions
%%%===================================================================
init() ->
    SoName =
        case code:priv_dir(?APPNAME) of
            {error, bad_name} ->
                case filelib:is_dir(filename:join(["..", priv])) of
                    true ->
                        filename:join(["..", priv, ?LIBNAME]);
                    _ ->
                        filename:join([priv, ?LIBNAME])
                end;
            Dir ->
                filename:join(Dir, ?LIBNAME)
        end,
    erlang:load_nif(SoName, 0).

not_loaded(Line) ->
    erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, Line}]}).
