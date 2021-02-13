#include "erl_nif.h"
#include "bpf.h"
#include <errno.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

/* copied from otp/erts/emulator/beam/erl_posix_str.c */
char *
erl_errno_id(error)
    int error;			/* Posix error number (as from errno). */
{
    switch (error) {
#ifdef E2BIG
    case E2BIG: return "e2big";
#endif
#ifdef EACCES
    case EACCES: return "eacces";
#endif
#ifdef EADDRINUSE
    case EADDRINUSE: return "eaddrinuse";
#endif
#ifdef EADDRNOTAVAIL
    case EADDRNOTAVAIL: return "eaddrnotavail";
#endif
#ifdef EADV
    case EADV: return "eadv";
#endif
#ifdef EAFNOSUPPORT
    case EAFNOSUPPORT: return "eafnosupport";
#endif
#ifdef EAGAIN
    case EAGAIN: return "eagain";
#endif
#ifdef EALIGN
    case EALIGN: return "ealign";
#endif
#if defined(EALREADY) && (!defined(EBUSY) || (EALREADY != EBUSY ))
    case EALREADY: return "ealready";
#endif
#ifdef EBADE
    case EBADE: return "ebade";
#endif
#ifdef EBADF
    case EBADF: return "ebadf";
#endif
#ifdef EBADFD
    case EBADFD: return "ebadfd";
#endif
#ifdef EBADMSG
    case EBADMSG: return "ebadmsg";
#endif
#ifdef EBADR
    case EBADR: return "ebadr";
#endif
#ifdef EBADRPC
    case EBADRPC: return "ebadrpc";
#endif
#ifdef EBADRQC
    case EBADRQC: return "ebadrqc";
#endif
#ifdef EBADSLT
    case EBADSLT: return "ebadslt";
#endif
#ifdef EBFONT
    case EBFONT: return "ebfont";
#endif
#ifdef EBUSY
    case EBUSY: return "ebusy";
#endif
#ifdef ECHILD
    case ECHILD: return "echild";
#endif
#ifdef ECHRNG
    case ECHRNG: return "echrng";
#endif
#ifdef ECOMM
    case ECOMM: return "ecomm";
#endif
#ifdef ECONNABORTED
    case ECONNABORTED: return "econnaborted";
#endif
#ifdef ECONNREFUSED
    case ECONNREFUSED: return "econnrefused";
#endif
#ifdef ECONNRESET
    case ECONNRESET: return "econnreset";
#endif
#if defined(EDEADLK) && (!defined(EWOULDBLOCK) || (EDEADLK != EWOULDBLOCK))
    case EDEADLK: return "edeadlk";
#endif
#if defined(EDEADLOCK) && (!defined(EDEADLK) || (EDEADLOCK != EDEADLK))
    case EDEADLOCK: return "edeadlock";
#endif
#ifdef EDESTADDRREQ
    case EDESTADDRREQ: return "edestaddrreq";
#endif
#ifdef EDIRTY
    case EDIRTY: return "edirty";
#endif
#ifdef EDOM
    case EDOM: return "edom";
#endif
#ifdef EDOTDOT
    case EDOTDOT: return "edotdot";
#endif
#ifdef EDQUOT
    case EDQUOT: return "edquot";
#endif
#ifdef EDUPPKG
    case EDUPPKG: return "eduppkg";
#endif
#ifdef EEXIST
    case EEXIST: return "eexist";
#endif
#ifdef EFAULT
    case EFAULT: return "efault";
#endif
#ifdef EFTYPE
    case EFTYPE: return "eftype";
#endif
#ifdef EFBIG
    case EFBIG: return "efbig";
#endif
#ifdef EHOSTDOWN
    case EHOSTDOWN: return "ehostdown";
#endif
#ifdef EHOSTUNREACH
    case EHOSTUNREACH: return "ehostunreach";
#endif
#if defined(EIDRM) && (!defined(EINPROGRESS) || (EIDRM != EINPROGRESS))
    case EIDRM: return "eidrm";
#endif
#ifdef EILSEQ
    case EILSEQ: return "eilseq";
#endif
#ifdef EINIT
    case EINIT: return "einit";
#endif
#ifdef EINPROGRESS
    case EINPROGRESS: return "einprogress";
#endif
#ifdef EINTR
    case EINTR: return "eintr";
#endif
#ifdef EINVAL
    case EINVAL: return "einval";
#endif
#ifdef EIO
    case EIO: return "eio";
#endif
#ifdef EISCONN
    case EISCONN: return "eisconn";
#endif
#ifdef EISDIR
    case EISDIR: return "eisdir";
#endif
#ifdef EISNAME
    case EISNAM: return "eisnam";
#endif
#ifdef ELBIN
    case ELBIN: return "elbin";
#endif
#ifdef EL2HLT
    case EL2HLT: return "el2hlt";
#endif
#ifdef EL2NSYNC
    case EL2NSYNC: return "el2nsync";
#endif
#ifdef EL3HLT
    case EL3HLT: return "el3hlt";
#endif
#ifdef EL3RST
    case EL3RST: return "el3rst";
#endif
#ifdef ELIBACC
    case ELIBACC: return "elibacc";
#endif
#ifdef ELIBBAD
    case ELIBBAD: return "elibbad";
#endif
#ifdef ELIBEXEC
    case ELIBEXEC: return "elibexec";
#endif
#ifdef ELIBMAX
    case ELIBMAX: return "elibmax";
#endif
#ifdef ELIBSCN
    case ELIBSCN: return "elibscn";
#endif
#ifdef ELNRNG
    case ELNRNG: return "elnrng";
#endif
#if defined(ELOOP) && (!defined(ENOENT) || (ELOOP != ENOENT))
    case ELOOP: return "eloop";
#endif
#ifdef EMFILE
    case EMFILE: return "emfile";
#endif
#ifdef EMLINK
    case EMLINK: return "emlink";
#endif
#ifdef EMSGSIZE
    case EMSGSIZE: return "emsgsize";
#endif
#ifdef EMULTIHOP
    case EMULTIHOP: return "emultihop";
#endif
#ifdef ENAMETOOLONG
    case ENAMETOOLONG: return "enametoolong";
#endif
#ifdef ENAVAIL
    case ENAVAIL: return "enavail";
#endif
#ifdef ENET
    case ENET: return "enet";
#endif
#ifdef ENETDOWN
    case ENETDOWN: return "enetdown";
#endif
#ifdef ENETRESET
    case ENETRESET: return "enetreset";
#endif
#ifdef ENETUNREACH
    case ENETUNREACH: return "enetunreach";
#endif
#ifdef ENFILE
    case ENFILE: return "enfile";
#endif
#ifdef ENOANO
    case ENOANO: return "enoano";
#endif
#if defined(ENOBUFS) && (!defined(ENOSR) || (ENOBUFS != ENOSR))
    case ENOBUFS: return "enobufs";
#endif
#ifdef ENOCSI
    case ENOCSI: return "enocsi";
#endif
#if defined(ENODATA) && (!defined(ECONNREFUSED) || (ENODATA != ECONNREFUSED))
    case ENODATA: return "enodata";
#endif
#ifdef ENODEV
    case ENODEV: return "enodev";
#endif
#ifdef ENOENT
    case ENOENT: return "enoent";
#endif
#ifdef ENOEXEC
    case ENOEXEC: return "enoexec";
#endif
#ifdef ENOLCK
    case ENOLCK: return "enolck";
#endif
#ifdef ENOLINK
    case ENOLINK: return "enolink";
#endif
#ifdef ENOMEM
    case ENOMEM: return "enomem";
#endif
#ifdef ENOMSG
    case ENOMSG: return "enomsg";
#endif
#ifdef ENONET
    case ENONET: return "enonet";
#endif
#ifdef ENOPKG
    case ENOPKG: return "enopkg";
#endif
#ifdef ENOPROTOOPT
    case ENOPROTOOPT: return "enoprotoopt";
#endif
#ifdef ENOSPC
    case ENOSPC: return "enospc";
#endif
#if defined(ENOSR) && (!defined(ENAMETOOLONG) || (ENAMETOOLONG != ENOSR))
    case ENOSR: return "enosr";
#endif
#if defined(ENOSTR) && (!defined(ENOTTY) || (ENOTTY != ENOSTR))
    case ENOSTR: return "enostr";
#endif
#ifdef ENOSYM
    case ENOSYM: return "enosym";
#endif
#ifdef ENOSYS
    case ENOSYS: return "enosys";
#endif
#ifdef ENOTBLK
    case ENOTBLK: return "enotblk";
#endif
#ifdef ENOTCONN
    case ENOTCONN: return "enotconn";
#endif
#ifdef ENOTDIR
    case ENOTDIR: return "enotdir";
#endif
#if defined(ENOTEMPTY) && (!defined(EEXIST) || (ENOTEMPTY != EEXIST))
    case ENOTEMPTY: return "enotempty";
#endif
#ifdef ENOTNAM
    case ENOTNAM: return "enotnam";
#endif
#ifdef ENOTSOCK
    case ENOTSOCK: return "enotsock";
#endif
#ifdef ENOTSUP
    case ENOTSUP: return "enotsup";
#endif
#ifdef ENOTTY
    case ENOTTY: return "enotty";
#endif
#ifdef ENOTUNIQ
    case ENOTUNIQ: return "enotuniq";
#endif
#ifdef ENXIO
    case ENXIO: return "enxio";
#endif
#if defined(EOPNOTSUPP) && (!defined(ENOTSUP) || (EOPNOTSUPP != ENOTSUP))
    case EOPNOTSUPP: return "eopnotsupp";
#endif
#ifdef EOVERFLOW
    case EOVERFLOW: return "eoverflow";
#endif
#ifdef EPERM
    case EPERM: return "eperm";
#endif
#if defined(EPFNOSUPPORT) && (!defined(ENOLCK) || (ENOLCK != EPFNOSUPPORT))
    case EPFNOSUPPORT: return "epfnosupport";
#endif
#ifdef EPIPE
    case EPIPE: return "epipe";
#endif
#ifdef EPROCLIM
    case EPROCLIM: return "eproclim";
#endif
#ifdef EPROCUNAVAIL
    case EPROCUNAVAIL: return "eprocunavail";
#endif
#ifdef EPROGMISMATCH
    case EPROGMISMATCH: return "eprogmismatch";
#endif
#ifdef EPROGUNAVAIL
    case EPROGUNAVAIL: return "eprogunavail";
#endif
#ifdef EPROTO
    case EPROTO: return "eproto";
#endif
#ifdef EPROTONOSUPPORT
    case EPROTONOSUPPORT: return "eprotonosupport";
#endif
#ifdef EPROTOTYPE
    case EPROTOTYPE: return "eprototype";
#endif
#ifdef ERANGE
    case ERANGE: return "erange";
#endif
#if defined(EREFUSED) && (!defined(ECONNREFUSED) || (EREFUSED != ECONNREFUSED))
    case EREFUSED: return "erefused";
#endif
#ifdef EREMCHG
    case EREMCHG: return "eremchg";
#endif
#ifdef EREMDEV
    case EREMDEV: return "eremdev";
#endif
#ifdef EREMOTE
    case EREMOTE: return "eremote";
#endif
#ifdef EREMOTEIO
    case EREMOTEIO: return "eremoteio";
#endif
#ifdef EREMOTERELEASE
    case EREMOTERELEASE: return "eremoterelease";
#endif
#ifdef EROFS
    case EROFS: return "erofs";
#endif
#ifdef ERPCMISMATCH
    case ERPCMISMATCH: return "erpcmismatch";
#endif
#ifdef ERREMOTE
    case ERREMOTE: return "erremote";
#endif
#ifdef ESHUTDOWN
    case ESHUTDOWN: return "eshutdown";
#endif
#ifdef ESOCKTNOSUPPORT
    case ESOCKTNOSUPPORT: return "esocktnosupport";
#endif
#ifdef ESPIPE
    case ESPIPE: return "espipe";
#endif
#ifdef ESRCH
    case ESRCH: return "esrch";
#endif
#ifdef ESRMNT
    case ESRMNT: return "esrmnt";
#endif
#ifdef ESTALE
    case ESTALE: return "estale";
#endif
#ifdef ESUCCESS
    case ESUCCESS: return "esuccess";
#endif
#if defined(ETIME) && (!defined(ELOOP) || (ETIME != ELOOP))
    case ETIME: return "etime";
#endif
#if defined(ETIMEDOUT) && (!defined(ENOSTR) || (ETIMEDOUT != ENOSTR)) && (!defined(EAGAIN) || (ETIMEDOUT != EAGAIN)) && (!defined(WSAETIMEDOUT) || (ETIMEDOUT != WSAETIMEDOUT))
    case ETIMEDOUT: return "etimedout";
#endif
#ifdef ETOOMANYREFS
    case ETOOMANYREFS: return "etoomanyrefs";
#endif
#ifdef ETXTBSY
    case ETXTBSY: return "etxtbsy";
#endif
#ifdef EUCLEAN
    case EUCLEAN: return "euclean";
#endif
#ifdef EUNATCH
    case EUNATCH: return "eunatch";
#endif
#ifdef EUSERS
    case EUSERS: return "eusers";
#endif
#ifdef EVERSION
    case EVERSION: return "eversion";
#endif
#if defined(EWOULDBLOCK) && (!defined(EAGAIN) || (EWOULDBLOCK != EAGAIN)) && (!defined(WSAEWOULDBLOCK) || (EWOULDBLOCK != WSAEWOULDBLOCK))
    case EWOULDBLOCK: return "ewouldblock";
#endif
#ifdef EXDEV
    case EXDEV: return "exdev";
#endif
#ifdef EXFULL
    case EXFULL: return "exfull";
#endif
#ifdef WSAEINTR
    case WSAEINTR: return "eintr";
#endif
#ifdef WSAEBADF
    case WSAEBADF: return "ebadf";
#endif
#ifdef WSAEACCES
    case WSAEACCES: return "eacces";
#endif
#ifdef WSAEFAULT
    case WSAEFAULT: return "efault";
#endif
#ifdef WSAEINVAL
    case WSAEINVAL: return "einval";
#endif
#ifdef WSAEMFILE
    case WSAEMFILE: return "emfile";
#endif
#ifdef WSAEWOULDBLOCK  
    case WSAEWOULDBLOCK: return "ewouldblock";
#endif
#ifdef WSAEINPROGRESS  
    case WSAEINPROGRESS: return "einprogress";
#endif
#ifdef WSAEALREADY     
    case WSAEALREADY: return "ealready";
#endif
#ifdef WSAENOTSOCK     
    case WSAENOTSOCK: return "enotsock";
#endif
#ifdef WSAEDESTADDRREQ 
    case WSAEDESTADDRREQ: return "edestaddrreq";
#endif
#ifdef WSAEMSGSIZE     
    case WSAEMSGSIZE: return "emsgsize";
#endif
#ifdef WSAEPROTOTYPE   
    case WSAEPROTOTYPE: return "eprototype";
#endif
#ifdef WSAENOPROTOOPT  
    case WSAENOPROTOOPT: return "enoprotoopt";
#endif
#ifdef WSAEPROTONOSUPPORT
    case WSAEPROTONOSUPPORT: return "eprotonosupport";
#endif
#ifdef WSAESOCKTNOSUPPORT
    case WSAESOCKTNOSUPPORT: return "esocktnosupport";
#endif
#ifdef WSAEOPNOTSUPP   
    case WSAEOPNOTSUPP: return "eopnotsupp";
#endif
#ifdef WSAEPFNOSUPPORT 
    case WSAEPFNOSUPPORT: return "epfnosupport";
#endif
#ifdef WSAEAFNOSUPPORT 
    case WSAEAFNOSUPPORT: return "eafnosupport";
#endif
#ifdef WSAEADDRINUSE   
    case WSAEADDRINUSE: return "eaddrinuse";
#endif
#ifdef WSAEADDRNOTAVAIL
    case WSAEADDRNOTAVAIL: return "eaddrnotavail";
#endif
#ifdef WSAENETDOWN    
    case WSAENETDOWN: return "enetdown";
#endif
#ifdef WSAENETUNREACH 
    case WSAENETUNREACH: return "enetunreach";
#endif
#ifdef WSAENETRESET   
    case WSAENETRESET: return "enetreset";
#endif
#ifdef WSAECONNABORTED
    case WSAECONNABORTED: return "econnaborted";
#endif
#ifdef WSAECONNRESET  
    case WSAECONNRESET: return "econnreset";
#endif
#ifdef WSAENOBUFS     
    case WSAENOBUFS: return "enobufs";
#endif
#ifdef WSAEISCONN     
    case WSAEISCONN: return "eisconn";
#endif
#ifdef WSAENOTCONN    
    case WSAENOTCONN: return "enotconn";
#endif
#ifdef WSAESHUTDOWN   
    case WSAESHUTDOWN: return "eshutdown";
#endif
#ifdef WSAETOOMANYREFS
    case WSAETOOMANYREFS: return "etoomanyrefs";
#endif
#ifdef WSAETIMEDOUT   
    case WSAETIMEDOUT: return "etimedout";
#endif
#ifdef WSAECONNREFUSED
    case WSAECONNREFUSED: return "econnrefused";
#endif
#ifdef WSAELOOP
    case WSAELOOP: return "eloop";
#endif
#ifdef WSAENAMETOOLONG
    case WSAENAMETOOLONG: return "enametoolong";
#endif
#ifdef WSAEHOSTDOWN
    case WSAEHOSTDOWN: return "ehostdown";
#endif
#ifdef WSAEHOSTUNREACH
    case WSAEHOSTUNREACH: return "ehostunreach";
#endif
#ifdef WSAENOTEMPTY
    case WSAENOTEMPTY: return "enotempty";
#endif
#ifdef WSAEPROCLIM
    case WSAEPROCLIM: return "eproclim";
#endif
#ifdef WSAEUSERS
    case WSAEUSERS: return "eusers";
#endif
#ifdef WSAEDQUOT
    case WSAEDQUOT: return "edquot";
#endif
#ifdef WSAESTALE
    case WSAESTALE: return "estale";
#endif
#ifdef WSAEREMOTE
    case WSAEREMOTE: return "eremote";
#endif
#ifdef WSASYSNOTREADY
    case WSASYSNOTREADY: return "sysnotready";
#endif
#ifdef WSAVERNOTSUPPORTED
    case WSAVERNOTSUPPORTED: return "vernotsupported";
#endif
#ifdef WSANOTINITIALISED
    case WSANOTINITIALISED: return "notinitialised";
#endif
#ifdef WSAEDISCON
    case WSAEDISCON: return "ediscon";
#endif
#ifdef WSAENOMORE
    case WSAENOMORE: return "enomore";
#endif
#ifdef WSAECANCELLED
    case WSAECANCELLED: return "ecancelled";
#endif
#ifdef WSAEINVALIDPROCTABLE
    case WSAEINVALIDPROCTABLE: return "einvalidproctable";
#endif
#ifdef WSAEINVALIDPROVIDER
    case WSAEINVALIDPROVIDER: return "einvalidprovider";
#endif
#ifdef WSAEPROVIDERFAILEDINIT
      /* You could get this if SYSTEMROOT env variable is set incorrectly */
    case WSAEPROVIDERFAILEDINIT: return "eproviderfailedinit";
#endif
#ifdef WSASYSCALLFAILURE
    case WSASYSCALLFAILURE: return "syscallfailure";
#endif
#ifdef WSASERVICE_NOT_FOUND
    case WSASERVICE_NOT_FOUND: return "service_not_found";
#endif
#ifdef WSATYPE_NOT_FOUND
    case WSATYPE_NOT_FOUND: return "type_not_found";
#endif
#ifdef WSA_E_NO_MORE
    case WSA_E_NO_MORE: return "e_no_more";
#endif
#ifdef WSA_E_CANCELLED
    case WSA_E_CANCELLED: return "e_cancelled";
#endif
    }
    return "unknown";
}

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
ebpf_attach_xdp(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  int prog_fd = -1;
  int if_index = -1;
  int res = 0;

  if(argc != 2)
    {
      return enif_make_badarg(env);
    }

  if(!enif_get_int(env, argv[0], &if_index))
    {
      return mk_error(env, "bad_if_index");
    }

  if(!enif_get_int(env, argv[1], &prog_fd))
    {
      return mk_error(env, "bad_fd");
    }

  res = bpf_set_link_xdp_fd(if_index, prog_fd, 0);

  if(res < 0){
    return mk_error(env, erl_errno_id(errno));
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
    return mk_error(env, erl_errno_id(errno));
  } else {
    return enif_make_tuple2(env, mk_atom(env, "ok"), enif_make_int(env, res));
  }

  return mk_atom(env, "ok");
}

static ERL_NIF_TERM
ebpf__verify_program(ErlNifEnv* env, int type, ErlNifBinary * bin, char * buf, size_t buf_size, uint32_t kernel_version, const char * license)
{
  int res = -1;
  int log_level = 1;

  if (buf == NULL)
    {
      buf_size = 0;
      log_level = 0;
    }

  res = bpf_verify_program(type,
			   (const struct bpf_insn *) bin->data,
			   bin->size / 8,
			   0,
			   license,
			   kernel_version,
			   buf,
			   buf_size,
			   log_level);
  if (res < 0)
    {
      if (errno == EACCES || errno == EINVAL)
	{
	  return enif_make_tuple3(env,
				  mk_atom(env, "error"),
				  mk_atom(env, erl_errno_id(errno)),
				  enif_make_string(env, buf, ERL_NIF_LATIN1));
	}
      else
	{
	  return mk_error(env, erl_errno_id(errno));
	}
    }
  else
    {
      return enif_make_tuple2(env, mk_atom(env, "ok"), enif_make_string(env, buf, ERL_NIF_LATIN1));
    }
}

static ERL_NIF_TERM
ebpf_verify_program5(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  int type = 0;
  ErlNifBinary bin = {0,};
  char * buf = NULL;
  uint32_t buf_size = 0;
  uint32_t kernel_version = 0;
  char license[256] = {0,};

  ERL_NIF_TERM res = {0,};

  if(argc != 5)
    {
      return enif_make_badarg(env);
    }

  if(!enif_get_int(env, argv[0], &type))
    {
      return enif_make_badarg(env);
    }


  if(!enif_inspect_binary(env, argv[1], &bin))
    {
      return enif_make_badarg(env);
    }

  if(!enif_get_uint(env, argv[2], &buf_size))
    {
      return enif_make_badarg(env);
    }

  if(!enif_get_uint(env, argv[3], &kernel_version))
    {
      return enif_make_badarg(env);
    }

  if(enif_get_string(env, argv[4], license, sizeof(license), ERL_NIF_LATIN1) <= 0)
    {
      return enif_make_badarg(env);
    }
  
  buf = (char *) malloc (buf_size);

  if(buf == NULL)
    {
      return mk_error(env, erl_errno_id(errno));
    }

  memset(buf, 0, buf_size);

  res = ebpf__verify_program(env, type, &bin, buf, buf_size, kernel_version, license);

  if (buf)
    {
      free(buf);
    }

  return res;
}

static ERL_NIF_TERM
ebpf_attach_socket_filter(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  int prog_fd = 0;
  int sock_fd = 0;
  int res = -1;

  if(argc != 2)
    {
      return enif_make_badarg(env);
    }

  if(!enif_get_int(env, argv[0], &sock_fd))
    {
      return mk_error(env, "bad_sock_fd");
    }

  if(!enif_get_int(env, argv[1], &prog_fd))
    {
      return mk_error(env, "bad_prog_fd");
    }

  res = setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd));
  if (res < 0) {
    return mk_error(env, erl_errno_id(errno));
  }

  return mk_atom(env, "ok");
}

static ERL_NIF_TERM
ebpf_create_map5(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  int map_type = 0;
  int key_size = 0;
  int value_size = 0;
  int max_entries = 0;
  __u32 map_flags = 0;

  int res = -1;

  if(argc != 5)
    {
      return enif_make_badarg(env);
    }

  if(!enif_get_int( env, argv[0], &map_type)
  || !enif_get_int( env, argv[1], &key_size)
  || !enif_get_int( env, argv[2], &value_size)
  || !enif_get_int( env, argv[3], &max_entries)
  || !enif_get_uint(env, argv[4], &map_flags))
    {
      return enif_make_badarg(env);
    }

  res = bpf_create_map(map_type, key_size, value_size, max_entries, map_flags);
  if (res < 0)
    {
      return mk_error(env, erl_errno_id(errno));
    }

  return enif_make_tuple2(env, mk_atom(env, "ok"), enif_make_int(env, res));
}

static ERL_NIF_TERM
ebpf_close1(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  int fd = -1;
  int res = -1;

  if (argc != 1)
    {
      return enif_make_badarg(env);
    }

  if(!enif_get_int( env, argv[0], &fd))
    {
      return enif_make_badarg(env);
    }

  do {
    res = close(fd);
  } while (errno == EINTR);

  if (res < 0)
    {
      return mk_error(env, erl_errno_id(errno));
    }

  return mk_atom(env, "ok");
}

static ErlNifFunc nif_funcs[] = {
				 {"bpf_load_program", 2, ebpf_load_program, 0},
				 {"bpf_attach_socket_filter", 2, ebpf_attach_socket_filter, 0},
				 {"bpf_attach_xdp", 2, ebpf_attach_xdp, 0},
				 {"bpf_verify_program", 5, ebpf_verify_program5, 0},
				 {"bpf_create_map", 5, ebpf_create_map5, 0},
				 {"bpf_close", 1, ebpf_close1, 0}
};

ERL_NIF_INIT(ebpf_lib, nif_funcs, NULL, NULL, NULL, NULL);
