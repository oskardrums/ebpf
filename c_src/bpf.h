#ifndef __BPF_H
#define __BPF_H

#include <linux/bpf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef min
# define min(x, y) ((x) < (y) ? (x) : (y))
#endif
#ifndef max
# define max(x, y) ((x) < (y) ? (y) : (x))
#endif
#ifndef offsetofend
# define offsetofend(TYPE, FIELD) \
	(offsetof(TYPE, FIELD) + sizeof(((TYPE *)0)->FIELD))
#endif

#define DECLARE_OPTS(TYPE, NAME, ...)				    \
	struct TYPE NAME = ({ 						    \
		memset(&NAME, 0, sizeof(struct TYPE));			    \
		(struct TYPE) {						    \
			.sz = sizeof(struct TYPE),			    \
			__VA_ARGS__					    \
		};							    \
	})


#ifndef __NR_bpf
# if defined(__i386__)
#  define __NR_bpf 357
# elif defined(__x86_64__)
#  define __NR_bpf 321
# elif defined(__aarch64__)
#  define __NR_bpf 280
# elif defined(__sparc__)
#  define __NR_bpf 349
# elif defined(__s390__)
#  define __NR_bpf 351
# elif defined(__arc__)
#  define __NR_bpf 280
# else
#  error __NR_bpf not defined. libbpf does not support your arch.
# endif
#endif


static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
			  unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

static inline int sys_bpf_prog_load(union bpf_attr *attr, unsigned int size)
{
	int retries = 5;
	int fd;

	do {
		fd = sys_bpf(BPF_PROG_LOAD, attr, size);
	} while (fd < 0 && errno == EAGAIN && retries-- > 0);

	return fd;
}


struct bpf_prog_load_params {
	enum bpf_prog_type prog_type;
	enum bpf_attach_type expected_attach_type;
	const char *name;
	const struct bpf_insn *insns;
	size_t insn_cnt;
	const char *license;
	__u32 kern_version;
	__u32 attach_prog_fd;
	__u32 attach_btf_obj_fd;
	__u32 attach_btf_id;
	__u32 prog_ifindex;
	__u32 prog_btf_fd;
	__u32 prog_flags;

	__u32 func_info_rec_size;
	const void *func_info;
	__u32 func_info_cnt;

	__u32 line_info_rec_size;
	const void *line_info;
	__u32 line_info_cnt;

	__u32 log_level;
	char *log_buf;
	size_t log_buf_sz;
};

static inline bool validate_opts(const char *opts,
					size_t opts_sz, size_t user_sz,
					const char *type_name)
{
        (void) type_name;
	if (user_sz < sizeof(size_t)) {
		return false;
	}
	if (user_sz > opts_sz) {
		size_t i;

		for (i = opts_sz; i < user_sz; i++) {
			if (opts[i]) {
				return false;
			}
		}
	}
	return true;
}

#define OPTS_VALID(opts, type)						      \
	(!(opts) || validate_opts((const char *)opts,		      \
					 offsetofend(struct type,	      \
						     type##__last_field),     \
					 (opts)->sz, #type))
#define OPTS_HAS(opts, field) \
	((opts) && opts->sz >= offsetofend(typeof(*(opts)), field))
#define OPTS_GET(opts, field, fallback_value) \
	(OPTS_HAS(opts, field) ? (opts)->field : fallback_value)
#define OPTS_SET(opts, field, value)		\
	do {					\
		if (OPTS_HAS(opts, field))	\
			(opts)->field = value;	\
	} while (0)

struct bpf_create_map_attr {
	const char *name;
	enum bpf_map_type map_type;
	__u32 map_flags;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 numa_node;
	__u32 btf_fd;
	__u32 btf_key_type_id;
	__u32 btf_value_type_id;
	__u32 map_ifindex;
	union {
		__u32 inner_map_fd;
		__u32 btf_vmlinux_value_type_id;
	};
};

int
bpf_create_map_xattr(const struct bpf_create_map_attr *create_attr);
int bpf_create_map_node(enum bpf_map_type map_type, const char *name,
				   int key_size, int value_size,
				   int max_entries, __u32 map_flags, int node);
int bpf_create_map_name(enum bpf_map_type map_type, const char *name,
				   int key_size, int value_size,
				   int max_entries, __u32 map_flags);
int bpf_create_map(enum bpf_map_type map_type, int key_size,
			      int value_size, int max_entries, __u32 map_flags);
int bpf_create_map_in_map_node(enum bpf_map_type map_type,
					  const char *name, int key_size,
					  int inner_map_fd, int max_entries,
					  __u32 map_flags, int node);
int bpf_create_map_in_map(enum bpf_map_type map_type,
				     const char *name, int key_size,
				     int inner_map_fd, int max_entries,
				     __u32 map_flags);

struct bpf_load_program_attr {
	enum bpf_prog_type prog_type;
	enum bpf_attach_type expected_attach_type;
	const char *name;
	const struct bpf_insn *insns;
	size_t insns_cnt;
	const char *license;
	union {
		__u32 kern_version;
		__u32 attach_prog_fd;
	};
	union {
		__u32 prog_ifindex;
		__u32 attach_btf_id;
	};
	__u32 prog_btf_fd;
	__u32 func_info_rec_size;
	const void *func_info;
	__u32 func_info_cnt;
	__u32 line_info_rec_size;
	const void *line_info;
	__u32 line_info_cnt;
	__u32 log_level;
	__u32 prog_flags;
};

/* Flags to direct loading requirements */
#define MAPS_RELAX_COMPAT	0x01

/* Recommend log buffer size */
#define BPF_LOG_BUF_SIZE (UINT32_MAX >> 8) /* verifier maximum in kernels <= 5.1 */
int
bpf_load_program_xattr(const struct bpf_load_program_attr *load_attr,
		       char *log_buf, size_t log_buf_sz);
int bpf_load_program(enum bpf_prog_type type,
				const struct bpf_insn *insns, size_t insns_cnt,
				const char *license, __u32 kern_version,
				char *log_buf, size_t log_buf_sz);
int bpf_verify_program(enum bpf_prog_type type,
				  const struct bpf_insn *insns,
				  size_t insns_cnt, __u32 prog_flags,
				  const char *license, __u32 kern_version,
				  char *log_buf, size_t log_buf_sz,
				  int log_level);

int bpf_map_update_elem(int fd, const void *key, const void *value,
				   __u64 flags);

int bpf_map_lookup_elem(int fd, const void *key, void *value);
int bpf_map_lookup_elem_flags(int fd, const void *key, void *value,
					 __u64 flags);
int bpf_map_lookup_and_delete_elem(int fd, const void *key,
					      void *value);
int bpf_map_delete_elem(int fd, const void *key);
int bpf_map_get_next_key(int fd, const void *key, void *next_key);
int bpf_map_freeze(int fd);

struct bpf_map_batch_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */
	__u64 elem_flags;
	__u64 flags;
};
#define bpf_map_batch_opts__last_field flags

int bpf_map_delete_batch(int fd, void *keys,
				    __u32 *count,
				    const struct bpf_map_batch_opts *opts);
int bpf_map_lookup_batch(int fd, void *in_batch, void *out_batch,
				    void *keys, void *values, __u32 *count,
				    const struct bpf_map_batch_opts *opts);
int bpf_map_lookup_and_delete_batch(int fd, void *in_batch,
					void *out_batch, void *keys,
					void *values, __u32 *count,
					const struct bpf_map_batch_opts *opts);
int bpf_map_update_batch(int fd, void *keys, void *values,
				    __u32 *count,
				    const struct bpf_map_batch_opts *opts);

int bpf_obj_pin(int fd, const char *pathname);
int bpf_obj_get(const char *pathname);

struct bpf_prog_attach_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */
	unsigned int flags;
	int replace_prog_fd;
};
#define bpf_prog_attach_opts__last_field replace_prog_fd

int bpf_prog_attach(int prog_fd, int attachable_fd,
			       enum bpf_attach_type type, unsigned int flags);
int bpf_prog_attach_xattr(int prog_fd, int attachable_fd,
				     enum bpf_attach_type type,
				     const struct bpf_prog_attach_opts *opts);
int bpf_prog_detach(int attachable_fd, enum bpf_attach_type type);
int bpf_prog_detach2(int prog_fd, int attachable_fd,
				enum bpf_attach_type type);

union bpf_iter_link_info; /* defined in up-to-date linux/bpf.h */
struct bpf_link_create_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */
	__u32 flags;
	union bpf_iter_link_info *iter_info;
	__u32 iter_info_len;
	__u32 target_btf_id;
};
#define bpf_link_create_opts__last_field target_btf_id

int bpf_link_create(int prog_fd, int target_fd,
			       enum bpf_attach_type attach_type,
			       const struct bpf_link_create_opts *opts);

int bpf_link_detach(int link_fd);

struct bpf_link_update_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */
	__u32 flags;	   /* extra flags */
	__u32 old_prog_fd; /* expected old program FD */
};
#define bpf_link_update_opts__last_field old_prog_fd

int bpf_link_update(int link_fd, int new_prog_fd,
			       const struct bpf_link_update_opts *opts);

int bpf_iter_create(int link_fd);

struct bpf_prog_test_run_attr {
	int prog_fd;
	int repeat;
	const void *data_in;
	__u32 data_size_in;
	void *data_out;      /* optional */
	__u32 data_size_out; /* in: max length of data_out
			      * out: length of data_out */
	__u32 retval;        /* out: return code of the BPF program */
	__u32 duration;      /* out: average per repetition in ns */
	const void *ctx_in; /* optional */
	__u32 ctx_size_in;
	void *ctx_out;      /* optional */
	__u32 ctx_size_out; /* in: max length of ctx_out
			     * out: length of cxt_out */
};

int bpf_prog_test_run_xattr(struct bpf_prog_test_run_attr *test_attr);

/*
 * bpf_prog_test_run does not check that data_out is large enough. Consider
 * using bpf_prog_test_run_xattr instead.
 */
int bpf_prog_test_run(int prog_fd, int repeat, void *data,
				 __u32 size, void *data_out, __u32 *size_out,
				 __u32 *retval, __u32 *duration);
int bpf_prog_get_next_id(__u32 start_id, __u32 *next_id);
int bpf_map_get_next_id(__u32 start_id, __u32 *next_id);
int bpf_btf_get_next_id(__u32 start_id, __u32 *next_id);
int bpf_link_get_next_id(__u32 start_id, __u32 *next_id);
int bpf_prog_get_fd_by_id(__u32 id);
int bpf_map_get_fd_by_id(__u32 id);
int bpf_btf_get_fd_by_id(__u32 id);
int bpf_link_get_fd_by_id(__u32 id);
int bpf_obj_get_info_by_fd(int bpf_fd, void *info, __u32 *info_len);
int bpf_prog_query(int target_fd, enum bpf_attach_type type,
			      __u32 query_flags, __u32 *attach_flags,
			      __u32 *prog_ids, __u32 *prog_cnt);
int bpf_raw_tracepoint_open(const char *name, int prog_fd);
int bpf_load_btf(const void *btf, __u32 btf_size, char *log_buf,
			    __u32 log_buf_size, bool do_log);
int bpf_task_fd_query(int pid, int fd, __u32 flags, char *buf,
				 __u32 *buf_len, __u32 *prog_id, __u32 *fd_type,
				 __u64 *probe_offset, __u64 *probe_addr);

enum bpf_stats_type; /* defined in up-to-date linux/bpf.h */
int bpf_enable_stats(enum bpf_stats_type type);

struct bpf_prog_bind_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */
	__u32 flags;
};
#define bpf_prog_bind_opts__last_field flags

int bpf_prog_bind_map(int prog_fd, int map_fd,
				 const struct bpf_prog_bind_opts *opts);

struct bpf_test_run_opts {
	size_t sz; /* size of this struct for forward/backward compatibility */
	const void *data_in; /* optional */
	void *data_out;      /* optional */
	__u32 data_size_in;
	__u32 data_size_out; /* in: max length of data_out
			      * out: length of data_out
			      */
	const void *ctx_in; /* optional */
	void *ctx_out;      /* optional */
	__u32 ctx_size_in;
	__u32 ctx_size_out; /* in: max length of ctx_out
			     * out: length of cxt_out
			     */
	__u32 retval;        /* out: return code of the BPF program */
	int repeat;
	__u32 duration;      /* out: average per repetition in ns */
	__u32 flags;
	__u32 cpu;
};
#define bpf_test_run_opts__last_field cpu

int bpf_prog_test_run_opts(int prog_fd,
				      struct bpf_test_run_opts *opts);
int bpf_set_link_xdp_fd(int ifindex, int fd, __u32 flags);
#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BPF_H */
