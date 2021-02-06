#include "erl_nif.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

ERL_NIF_TERM
mk_atom(ErlNifEnv* env, const char* atom)
{
  ERL_NIF_TERM ret;

  if(!enif_make_existing_atom(env, atom, &ret, ERL_NIF_LATIN1))
    {
      return enif_make_atom(env, atom);
    }

  return ret;
}

ERL_NIF_TERM
mk_error(ErlNifEnv* env, const char* mesg)
{
  return enif_make_tuple2(env, mk_atom(env, "error"), mk_atom(env, mesg));
}

static ERL_NIF_TERM
xdp(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  int prog_fd = -1;
  int if_index = -1;
  ErlNifBinary binary_intructions = {0,};

  if(argc != 2)
    {
      return enif_make_badarg(env);
    }

  if(!enif_get_int(env, argv[0], &if_index))
    {
      return mk_error(env, "bad_if_index");
    }

  if(!enif_inspect_binary(env, argv[1], &binary_intructions))
    {
      return mk_error(env, "not_a_binary");
    }

  prog_fd = bpf_load_program(
			     BPF_PROG_TYPE_XDP,
			     (const struct bpf_insn *)binary_intructions.data,
			     binary_intructions.size / 8,
			     "GPL",
			     0,
			     NULL,
			     0);
  if (prog_fd < 0) {
    return mk_error(env, "bpf_load_program");
  }
  if (bpf_set_link_xdp_fd(if_index, prog_fd, 0) < 0) {
    return mk_error(env, "bpf_set_link_xdp_fd");
  }
  return mk_atom(env, "ok");
}

static ERL_NIF_TERM
ebpf_load_program(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  ErlNifBinary binary_intructions = {0,};
  int res = -1;
  int prog_type = 0;
  if(argc != 2)
    {
      return enif_make_badarg(env);
    }
  if(!enif_get_int(env, argv[0], &prog_type))
    {
      return mk_error(env, "bad_prog_type");
    }
  if(!enif_inspect_binary(env, argv[1], &binary_intructions))
    {
      return mk_error(env, "not_a_binary");
    }
  res = bpf_load_program(prog_type,
			 (const struct bpf_insn *) binary_intructions.data,
			 binary_intructions.size / 8,
			 "GPL",
			 0,
			 NULL,
			 0);
  if (res < 0) {
    return mk_atom(env, "error");
  } else {
    return enif_make_tuple2(env, mk_atom(env, "ok"), enif_make_int(env, res));
  }

  return mk_atom(env, "ok");
}

static ERL_NIF_TERM
ebpf_verify_program(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  ErlNifBinary binary_intructions = {0,};
  char buf[4096];
  int res = -1;
  int prog_type = 0;
 
  if(argc != 2)
    {
      return enif_make_badarg(env);
    }

  if(!enif_get_int(env, argv[0], &prog_type))
    {
      return mk_error(env, "bad_prog_type");
    }


  if(!enif_inspect_binary(env, argv[1], &binary_intructions))
    {
      return mk_error(env, "not_a_binary");
    }

  res = bpf_verify_program(prog_type,
			   (const struct bpf_insn *) binary_intructions.data,
			   binary_intructions.size / 8,
			   0,
			   "GPL",
			   0,
			   buf,
			   sizeof(buf),
			   1);
  if (res < 0) {
    return enif_make_tuple2(env, mk_atom(env, "error"), enif_make_string(env, buf, ERL_NIF_LATIN1));
  }

  return mk_atom(env, "ok");
}

static ErlNifFunc nif_funcs[] = {
				 {"ebpf_load_program", 2, ebpf_load_program},
				 {"ebpf_verify_program", 2, ebpf_verify_program}
};

ERL_NIF_INIT(ebpf_lib, nif_funcs, NULL, NULL, NULL, NULL);
