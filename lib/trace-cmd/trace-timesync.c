// SPDX-License-Identifier: LGPL-2.1
/*
 * Copyright (C) 2019, VMware, Tzvetomir Stoyanov <tz.stoyanov@gmail.com>
 *
 */

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/vm_sockets.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>

#include "trace-cmd-private.h"
#include "tracefs.h"
#include "event-utils.h"
#include "trace-tsync-local.h"

struct tsync_proto {
	struct tsync_proto *next;
	char proto_name[TRACECMD_TSYNC_PNAME_LENGTH];
	enum tracecmd_time_sync_role roles;
	int accuracy;
	int supported_clocks;
	unsigned int flags;

	int (*clock_sync_init)(struct tracecmd_time_sync *clock_context);
	int (*clock_sync_free)(struct tracecmd_time_sync *clock_context);
	int (*clock_sync_calc)(struct tracecmd_time_sync *clock_context,
			       long long *offset, long long *scaling,
			       long long *timestamp, unsigned int cpu);
};

struct tsync_probe_request_msg {
	unsigned short	cpu;
} __packed;

static struct tsync_proto *tsync_proto_list;

static struct tsync_proto *tsync_proto_find(const char *proto_name)
{
	struct tsync_proto *proto;

	if (!proto_name)
		return NULL;
	for (proto = tsync_proto_list; proto; proto = proto->next) {
		if (strlen(proto->proto_name) == strlen(proto_name) &&
		     !strncmp(proto->proto_name, proto_name, TRACECMD_TSYNC_PNAME_LENGTH))
			return proto;
	}
	return NULL;
}

/**
 * tracecmd_tsync_init - Initialize the global, per task, time sync data.
 */
void tracecmd_tsync_init(void)
{
	ptp_clock_sync_register();
}

int tracecmd_tsync_proto_register(const char *proto_name, int accuracy, int roles,
				  int supported_clocks, unsigned int flags,
				  int (*init)(struct tracecmd_time_sync *),
				  int (*free)(struct tracecmd_time_sync *),
				  int (*calc)(struct tracecmd_time_sync *,
					      long long *, long long *,
					      long long *, unsigned int))
{
	struct tsync_proto *proto = NULL;

	if (tsync_proto_find(proto_name))
		return -1;
	proto = calloc(1, sizeof(struct tsync_proto));
	if (!proto)
		return -1;
	strncpy(proto->proto_name, proto_name, TRACECMD_TSYNC_PNAME_LENGTH);
	proto->accuracy = accuracy;
	proto->roles = roles;
	proto->flags = flags;
	proto->supported_clocks = supported_clocks;
	proto->clock_sync_init = init;
	proto->clock_sync_free = free;
	proto->clock_sync_calc = calc;

	proto->next = tsync_proto_list;
	tsync_proto_list = proto;
	return 0;
}

int tracecmd_tsync_proto_unregister(char *proto_name)
{
	struct tsync_proto **last = &tsync_proto_list;

	if (!proto_name)
		return -1;

	for (; *last; last = &(*last)->next) {
		if (strlen((*last)->proto_name) == strlen(proto_name) &&
		    !strncmp((*last)->proto_name, proto_name, TRACECMD_TSYNC_PNAME_LENGTH)) {
			struct tsync_proto *proto = *last;

			*last = proto->next;
			free(proto);
			return 0;
		}
	}

	return -1;
}

bool tsync_proto_is_supported(const char *proto_name)
{
	if (tsync_proto_find(proto_name))
		return true;
	return false;
}

/**
 * tracecmd_tsync_get_offsets - Return the calculated time offsets
 *
 * @tsync: Pointer to time sync context
 * @cpu: CPU for which to get the calculated offsets
 * @count: Returns the number of calculated time offsets
 * @ts: Array of size @count containing timestamps of callculated offsets
 * @offsets: array of size @count, containing offsets for each timestamp
 * @scalings: array of size @count, containing scaling ratios for each timestamp
 *
 * Retuns -1 in case of an error, or 0 otherwise
 */
int tracecmd_tsync_get_offsets(struct tracecmd_time_sync *tsync, int cpu,
				int *count, long long **ts,
				long long **offsets, long long **scalings)
{
	struct clock_sync_context *tsync_context;

	if (!tsync || !tsync->context)
		return -1;
	tsync_context = (struct clock_sync_context *)tsync->context;
	if (cpu >= tsync_context->cpu_count || !tsync_context->offsets)
		return -1;
	if (count)
		*count = tsync_context->offsets[cpu].sync_count;
	if (ts)
		*ts = tsync_context->offsets[cpu].sync_ts;
	if (offsets)
		*offsets = tsync_context->offsets[cpu].sync_offsets;
	if (scalings)
		*scalings = tsync_context->offsets[cpu].sync_scalings;

	return 0;
}

/**
 * tracecmd_tsync_get_proto_flags - Get protocol flags
 *
 * @tsync: Pointer to time sync context
 * @flags: Returns the protocol flags, a combination of TRACECMD_TSYNC_FLAG_...
 *
 * Retuns -1 in case of an error, or 0 otherwise
 */
int tracecmd_tsync_get_proto_flags(struct tracecmd_time_sync *tsync,
				   unsigned int *flags)
{
	struct tsync_proto *protocol;

	if (!tsync)
		return -1;
	protocol = tsync_proto_find(tsync->proto_name);
	if (!protocol)
		return -1;

	if (flags)
		*flags = protocol->flags;

	return 0;
}


#define PROTO_MASK_SIZE (sizeof(char))
#define PROTO_MASK_BITS (PROTO_MASK_SIZE * 8)
/**
 * tracecmd_tsync_proto_select - Select time sync protocol, to be used for
 *		timestamp synchronization with a peer
 *
 * @protos: list of tsync protocol names
 * @clock : trace clock
 * @role : local time sync role
 *
 * Retuns pointer to a protocol name, that can be used with the peer, or NULL
 *	  in case there is no match with supported protocols.
 *	  The returned string MUST NOT be freed by the caller
 */
const char *tracecmd_tsync_proto_select(struct tracecmd_tsync_protos *protos, char *clock,
				  enum tracecmd_time_sync_role role)
{
	struct tsync_proto *selected = NULL;
	struct tsync_proto *proto;
	char **pname;
	int clock_id = 0;

	if (!protos)
		return NULL;

	clock_id = tracecmd_clock_str2id(clock);
	pname = protos->names;
	while (*pname) {
		for (proto = tsync_proto_list; proto; proto = proto->next) {
			if (!(proto->roles & role))
				continue;
			if (proto->supported_clocks && clock_id &&
			    !(proto->supported_clocks & clock_id))
				continue;
			if (strncmp(proto->proto_name, *pname, TRACECMD_TSYNC_PNAME_LENGTH))
				continue;
			if (selected) {
				if (selected->accuracy > proto->accuracy)
					selected = proto;
			} else
				selected = proto;
		}
		pname++;
	}

	if (selected)
		return selected->proto_name;

	return NULL;
}

/**
 * tracecmd_tsync_proto_getall - Returns bitmask of all supported
 *				 time sync protocols
 * @protos: return, allocated list of time sync protocol names,
 *	       supported by the peer. Must be freed by free()
 * @clock: selected trace clock
 * @role: supported protocol role
 *
 * If completed successfully 0 is returned and allocated list of strings in @protos.
 * The last list entry is NULL. In case of an error, -1 is returned.
 * @protos must be freed with free()
 */
int tracecmd_tsync_proto_getall(struct tracecmd_tsync_protos **protos, const char *clock, int role)
{
	struct tracecmd_tsync_protos *plist = NULL;
	struct tsync_proto *proto;
	int clock_id = 0;
	int count = 1;
	int i;

	if (clock)
		clock_id =  tracecmd_clock_str2id(clock);
	for (proto = tsync_proto_list; proto; proto = proto->next) {
		if (!(proto->roles & role))
			continue;
		if (proto->supported_clocks && clock_id &&
		    !(proto->supported_clocks & clock_id))
			continue;
		count++;
	}
	plist = calloc(1, sizeof(struct tracecmd_tsync_protos));
	if (!plist)
		goto error;
	plist->names = calloc(count, sizeof(char *));
	if (!plist->names)
		return -1;

	for (i = 0, proto = tsync_proto_list; proto && i < (count - 1); proto = proto->next) {
		if (!(proto->roles & role))
			continue;
		if (proto->supported_clocks && clock_id &&
		    !(proto->supported_clocks & clock_id))
			continue;
		plist->names[i++] = proto->proto_name;
	}

	*protos = plist;
	return 0;

error:
	if (plist) {
		free(plist->names);
		free(plist);
	}
	return -1;
}

static int get_vsocket_params(int fd, unsigned int *lcid, unsigned int *lport,
			      unsigned int *rcid, unsigned int *rport)
{
	struct sockaddr_vm addr;
	socklen_t addr_len = sizeof(addr);

	memset(&addr, 0, sizeof(addr));
	if (getsockname(fd, (struct sockaddr *)&addr, &addr_len))
		return -1;
	if (addr.svm_family != AF_VSOCK)
		return -1;
	*lport = addr.svm_port;
	*lcid = addr.svm_cid;

	memset(&addr, 0, sizeof(addr));
	addr_len = sizeof(addr);
	if (getpeername(fd, (struct sockaddr *)&addr, &addr_len))
		return -1;
	if (addr.svm_family != AF_VSOCK)
		return -1;
	*rport = addr.svm_port;
	*rcid = addr.svm_cid;

	return 0;
}

static struct tracefs_instance *
clock_synch_create_instance(const char *clock, unsigned int cid)
{
	struct tracefs_instance *instance;
	char inst_name[256];

	snprintf(inst_name, 256, "clock_synch-%d", cid);

	instance = tracefs_instance_create(inst_name);
	if (!instance)
		return NULL;

	tracefs_instance_file_write(instance, "trace", "\0");
	if (clock)
		tracefs_instance_file_write(instance, "trace_clock", clock);
	return instance;
}

static void
clock_synch_delete_instance(struct tracefs_instance *inst)
{
	if (!inst)
		return;
	tracefs_instance_destroy(inst);
	tracefs_instance_free(inst);
}

static int clock_context_init(struct tracecmd_time_sync *tsync, bool guest)
{
	struct clock_sync_context *clock = NULL;
	struct tsync_proto *protocol;

	if (tsync->context)
		return 0;

	protocol = tsync_proto_find(tsync->proto_name);
	if (!protocol)
		return -1;

	clock = calloc(1, sizeof(struct clock_sync_context));
	if (!clock)
		return -1;
	clock->is_guest = guest;
	clock->is_server = clock->is_guest;

	if (get_vsocket_params(tsync->msg_handle->fd, &clock->local_cid,
			       &clock->local_port, &clock->remote_cid,
			       &clock->remote_port))
		goto error;

	clock->instance = clock_synch_create_instance(tsync->clock_str,
						      clock->remote_cid);
	if (!clock->instance)
		goto error;

	clock->cpu_count = tsync->vcpu_count;
	if (clock->cpu_count) {
		clock->offsets = calloc(clock->cpu_count, sizeof(struct clock_sync_offsets));
		if (!clock->offsets)
			goto error;
	}

	tsync->context = clock;
	if (protocol->clock_sync_init && protocol->clock_sync_init(tsync) < 0)
		goto error;

	return 0;
error:
	tsync->context = NULL;
	if (clock->instance)
		clock_synch_delete_instance(clock->instance);
	free(clock->offsets);
	free(clock);
	return -1;
}

/**
 * tracecmd_tsync_free - Free time sync context, allocated by
 *		tracecmd_tsync_with_host() or tracecmd_tsync_with_guest() APIs
 *
 * @tsync: Pointer to time sync context
 *
 */
void tracecmd_tsync_free(struct tracecmd_time_sync *tsync)
{
	struct clock_sync_context *tsync_context;
	struct tsync_proto *proto;
	int i;

	if (!tsync->context)
		return;
	tsync_context = (struct clock_sync_context *)tsync->context;

	proto = tsync_proto_find(tsync->proto_name);
	if (proto && proto->clock_sync_free)
		proto->clock_sync_free(tsync);

	clock_synch_delete_instance(tsync_context->instance);
	tsync_context->instance = NULL;

	if (tsync_context->cpu_count && tsync_context->offsets) {
		for (i = 0; i < tsync_context->cpu_count; i++) {
			free(tsync_context->offsets[i].sync_ts);
			free(tsync_context->offsets[i].sync_offsets);
			free(tsync_context->offsets[i].sync_scalings);
			tsync_context->offsets[i].sync_ts = NULL;
			tsync_context->offsets[i].sync_offsets = NULL;
			tsync_context->offsets[i].sync_scalings = NULL;
			tsync_context->offsets[i].sync_count = 0;
			tsync_context->offsets[i].sync_size = 0;
		}
		free(tsync_context->offsets);
		tsync_context->offsets = NULL;
	}
	pthread_mutex_destroy(&tsync->lock);
	pthread_cond_destroy(&tsync->cond);
	free(tsync->clock_str);
}

static cpu_set_t *pin_to_cpu(int cpu)
{
	static size_t size;
	static int cpus;
	cpu_set_t *mask = NULL;
	cpu_set_t *old = NULL;

	if (!cpus) {
		cpus = tracecmd_count_cpus();
		size = CPU_ALLOC_SIZE(cpus);
	}
	if (cpu >= cpus)
		goto error;

	mask = CPU_ALLOC(cpus);
	if (!mask)
		goto error;
	old = CPU_ALLOC(cpus);
	if (!old)
		goto error;

	CPU_ZERO_S(size, mask);
	CPU_SET_S(cpu, size, mask);
	if (pthread_getaffinity_np(pthread_self(), size, old))
		goto error;
	if (pthread_setaffinity_np(pthread_self(), size, mask))
		goto error;

	CPU_FREE(mask);
	return old;

error:
	if (mask)
		CPU_FREE(mask);
	if (old)
		CPU_FREE(old);
	return NULL;
}

static void restore_pin_to_cpu(cpu_set_t *mask)
{
	static size_t size;

	if (!size)
		size = CPU_ALLOC_SIZE(tracecmd_count_cpus());

	pthread_setaffinity_np(pthread_self(), size, mask);
	CPU_FREE(mask);
}

int tracecmd_tsync_send(struct tracecmd_time_sync *tsync,
			struct tsync_proto *proto, unsigned int cpu)
{
	cpu_set_t *old_set = NULL;
	long long timestamp = 0;
	long long scaling = 0;
	long long offset = 0;
	int ret;

	old_set = pin_to_cpu(cpu);
	ret = proto->clock_sync_calc(tsync, &offset, &scaling, &timestamp, cpu);
	if (old_set)
		restore_pin_to_cpu(old_set);

	return ret;
}

/**
 * tracecmd_tsync_with_host - Synchronize timestamps with host
 *
 * @tsync: Pointer to time sync context
 *
 * This API is supposed to be called in guest context. It waits for a time
 * sync request from the host and replies with a time sample, until time sync
 * stop command is received
 *
 */
void tracecmd_tsync_with_host(struct tracecmd_time_sync *tsync)
{
	char protocol[TRACECMD_TSYNC_PNAME_LENGTH];
	struct tsync_probe_request_msg probe;
	struct tsync_proto *proto;
	unsigned int command;
	unsigned int size;
	char *msg;
	int ret;

	proto = tsync_proto_find(tsync->proto_name);
	if (!proto || !proto->clock_sync_calc)
		return;

	clock_context_init(tsync, true);
	if (!tsync->context)
		return;

	msg = (char *)&probe;
	size = sizeof(probe);
	while (true) {
		memset(&probe, 0, size);
		ret = tracecmd_msg_recv_time_sync(tsync->msg_handle,
						  protocol, &command,
						  &size, &msg);

		if (ret || strncmp(protocol, TRACECMD_TSYNC_PROTO_NONE, TRACECMD_TSYNC_PNAME_LENGTH) ||
		    command != TRACECMD_TIME_SYNC_CMD_PROBE)
			break;
		ret = tracecmd_tsync_send(tsync, proto, probe.cpu);
		if (ret)
			break;
	}
}

static int record_sync_sample(struct clock_sync_offsets *offsets, int array_step,
			      long long offset, long long scaling, long long ts)
{
	long long *sync_scalings = NULL;
	long long *sync_offsets = NULL;
	long long *sync_ts = NULL;

	if (offsets->sync_count >= offsets->sync_size) {
		sync_ts = realloc(offsets->sync_ts,
				  (offsets->sync_size + array_step) * sizeof(long long));
		sync_offsets = realloc(offsets->sync_offsets,
				       (offsets->sync_size + array_step) * sizeof(long long));
		sync_scalings = realloc(offsets->sync_scalings,
				       (offsets->sync_size + array_step) * sizeof(long long));

		if (!sync_ts || !sync_offsets || !sync_scalings) {
			free(sync_ts);
			free(sync_offsets);
			free(sync_scalings);
			return -1;
		}
		offsets->sync_size += array_step;
		offsets->sync_ts = sync_ts;
		offsets->sync_offsets = sync_offsets;
		offsets->sync_scalings = sync_scalings;
	}

	offsets->sync_ts[offsets->sync_count] = ts;
	offsets->sync_offsets[offsets->sync_count] = offset;
	offsets->sync_scalings[offsets->sync_count] = scaling;
	offsets->sync_count++;

	return 0;
}

static int tsync_get_sample(struct tracecmd_time_sync *tsync, unsigned int cpu,
			    struct tsync_proto *proto, int array_step)
{
	struct clock_sync_context *clock;
	long long timestamp = 0;
	long long scaling = 0;
	long long offset = 0;
	int ret;

	ret = proto->clock_sync_calc(tsync, &offset, &scaling, &timestamp, cpu);
	if (ret) {
		warning("Failed to synchronize timestamps with guest");
		return -1;
	}
	if (!offset || !timestamp || !scaling)
		return 0;
	clock = tsync->context;
	if (!clock || cpu >= clock->cpu_count || !clock->offsets)
		return -1;
	return record_sync_sample(&clock->offsets[cpu], array_step,
				  offset, scaling, timestamp);
}

#define TIMER_SEC_NANO 1000000000LL
static inline void get_ts_loop_delay(struct timespec *timeout, int delay_ms)
{
	memset(timeout, 0, sizeof(struct timespec));
	clock_gettime(CLOCK_REALTIME, timeout);

	timeout->tv_nsec += ((unsigned long long)delay_ms * 1000000LL);

	if (timeout->tv_nsec >= TIMER_SEC_NANO) {
		timeout->tv_sec += timeout->tv_nsec / TIMER_SEC_NANO;
		timeout->tv_nsec %= TIMER_SEC_NANO;
	}
}

#define CLOCK_TS_ARRAY 5
/**
 * tracecmd_tsync_with_guest - Synchronize timestamps with guest
 *
 * @tsync: Pointer to time sync context
 *
 * This API is supposed to be called in host context, in a separate thread
 * It loops infinite, until the timesync semaphore is released
 *
 */
void tracecmd_tsync_with_guest(struct tracecmd_time_sync *tsync)
{
	struct tsync_probe_request_msg probe;
	int ts_array_size = CLOCK_TS_ARRAY;
	struct tsync_proto *proto;
	struct timespec timeout;
	bool end = false;
	int ret;
	int i;

	proto = tsync_proto_find(tsync->proto_name);
	if (!proto || !proto->clock_sync_calc)
		return;

	clock_context_init(tsync, false);
	if (!tsync->context)
		return;

	if (tsync->loop_interval > 0 &&
	    tsync->loop_interval < (CLOCK_TS_ARRAY * 1000))
		ts_array_size = (CLOCK_TS_ARRAY * 1000) / tsync->loop_interval;

	while (true) {
		pthread_mutex_lock(&tsync->lock);
		for (i = 0; i < tsync->vcpu_count; i++) {
			probe.cpu = i;
			ret = tracecmd_msg_send_time_sync(tsync->msg_handle,
							  TRACECMD_TSYNC_PROTO_NONE,
							  TRACECMD_TIME_SYNC_CMD_PROBE,
							  sizeof(probe), (char *)&probe);
			ret = tsync_get_sample(tsync, i, proto, ts_array_size);
			if (ret)
				break;
		}
		if (end || i < tsync->vcpu_count)
			break;
		if (tsync->loop_interval > 0) {
			get_ts_loop_delay(&timeout, tsync->loop_interval);
			ret = pthread_cond_timedwait(&tsync->cond, &tsync->lock, &timeout);
			pthread_mutex_unlock(&tsync->lock);
			if (ret && ret != ETIMEDOUT)
				break;
			else if (!ret)
				end = true;
		} else {
			pthread_cond_wait(&tsync->cond, &tsync->lock);
			end = true;
			pthread_mutex_unlock(&tsync->lock);
		}
	};

	tracecmd_msg_send_time_sync(tsync->msg_handle,
				    TRACECMD_TSYNC_PROTO_NONE,
				    TRACECMD_TIME_SYNC_CMD_STOP,
				    0, NULL);
}
