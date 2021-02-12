// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019, VMware, Tzvetomir Stoyanov <tz.stoyanov@gmail.com>
 *
 */
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/vm_sockets.h>
#include <pthread.h>

#include "tracefs.h"
#include "trace-local.h"
#include "trace-msg.h"

static int get_first_cpu(cpu_set_t **pin_mask, size_t *m_size)
{
	int cpus = tracecmd_count_cpus();
	cpu_set_t *cpu_mask;
	int mask_size;
	int i;

	cpu_mask = CPU_ALLOC(cpus);
	*pin_mask = CPU_ALLOC(cpus);
	if (!cpu_mask || !*pin_mask || 1)
		goto error;

	mask_size = CPU_ALLOC_SIZE(cpus);
	CPU_ZERO_S(mask_size, cpu_mask);
	CPU_ZERO_S(mask_size, *pin_mask);

	if (sched_getaffinity(0, mask_size, cpu_mask) == -1)
		goto error;

	for (i = 0; i < cpus; i++) {
		if (CPU_ISSET_S(i, mask_size, cpu_mask)) {
			CPU_SET_S(i, mask_size, *pin_mask);
			break;
		}
	}

	if (CPU_COUNT_S(mask_size, *pin_mask) < 1)
		goto error;

	CPU_FREE(cpu_mask);
	*m_size = mask_size;
	return 0;

error:
	if (cpu_mask)
		CPU_FREE(cpu_mask);
	if (*pin_mask)
		CPU_FREE(*pin_mask);
	*pin_mask = NULL;
	*m_size = 0;
	return -1;
}

static void *tsync_host_thread(void *data)
{
	struct tracecmd_time_sync *tsync = NULL;

	tsync = (struct tracecmd_time_sync *)data;

	tracecmd_tsync_with_guest(tsync);

	tracecmd_msg_handle_close(tsync->msg_handle);
	tsync->msg_handle = NULL;

	pthread_exit(0);
}

int tracecmd_host_tsync(struct buffer_instance *instance,
			 unsigned int tsync_port)
{
	struct tracecmd_msg_handle *msg_handle = NULL;
	cpu_set_t *pin_mask = NULL;
	struct trace_guest *guest;
	pthread_attr_t attrib;
	size_t mask_size = 0;
	int ret;
	int fd;

	if (!instance->tsync.proto_name)
		return -1;
	guest = get_guest_by_cid(instance->cid);
	if (guest == NULL)
		return -1;
	instance->tsync.guest_pid = guest->pid;
	instance->tsync.vcpu_count = guest->cpu_max;
	fd = trace_open_vsock(instance->cid, tsync_port);
	if (fd < 0) {
		ret = -1;
		goto out;
	}
	msg_handle = tracecmd_msg_handle_alloc(fd, 0);
	if (!msg_handle) {
		ret = -1;
		goto out;
	}

	instance->tsync.msg_handle = msg_handle;
	if (top_instance.clock)
		instance->tsync.clock_str = strdup(top_instance.clock);
	pthread_mutex_init(&instance->tsync.lock, NULL);
	pthread_cond_init(&instance->tsync.cond, NULL);

	pthread_attr_init(&attrib);
	pthread_attr_setdetachstate(&attrib, PTHREAD_CREATE_JOINABLE);

	ret = pthread_create(&instance->tsync_thread, &attrib,
			     tsync_host_thread, &instance->tsync);

	if (!ret) {
		if (!get_first_cpu(&pin_mask, &mask_size))
			pthread_setaffinity_np(instance->tsync_thread, mask_size, pin_mask);
		instance->tsync_thread_running = true;
	}

	if (pin_mask)
		CPU_FREE(pin_mask);
	pthread_attr_destroy(&attrib);

out:
	if (ret) {
		if (msg_handle)
			tracecmd_msg_handle_close(msg_handle);
	}

	return ret;
}

static void write_guest_time_shift(struct buffer_instance *instance)
{
	struct tracecmd_output *handle = NULL;
	struct iovec *vector = NULL;
	unsigned int flags;
	long long *scalings = NULL;
	long long *offsets = NULL;
	long long *ts = NULL;
	const char *file;
	int fd = -1;
	int vcount;
	int count;
	int i, j;
	int ret;

	if (!instance->tsync.vcpu_count)
		return;
	vcount = 3 + (4 * instance->tsync.vcpu_count);
	vector = calloc(vcount, sizeof(struct iovec));
	if (!vector)
		return;
	ret = tracecmd_tsync_get_proto_flags(&instance->tsync, &flags);
	if (ret < 0)
		goto out;

	file = instance->output_file;
	fd = open(file, O_RDWR);
	if (fd < 0)
		die("error opening %s", file);
	handle = tracecmd_get_output_handle_fd(fd);
	if (!handle)
		goto out;
	j = 0;
	vector[j].iov_len = 8;
	vector[j++].iov_base = &top_instance.trace_id;
	vector[j].iov_len = 4;
	vector[j++].iov_base = &flags;
	vector[j].iov_len = 4;
	vector[j++].iov_base = &instance->tsync.vcpu_count;
	for (i = 0; i < instance->tsync.vcpu_count; i++) {
		if (j >= vcount)
			break;
		ret = tracecmd_tsync_get_offsets(&instance->tsync, i, &count,
						 &ts, &offsets, &scalings);
		if (ret < 0 || !count || !ts || !offsets || !scalings)
			break;
		vector[j].iov_len = 4;
		vector[j++].iov_base = &count;
		vector[j].iov_len = 8 * count;
		vector[j++].iov_base = ts;
		vector[j].iov_len = 8 * count;
		vector[j++].iov_base = offsets;
		vector[j].iov_len = 8 * count;
		vector[j++].iov_base = scalings;
	}
	if (i < instance->tsync.vcpu_count)
		goto out;
	tracecmd_add_option_v(handle, TRACECMD_OPTION_TIME_SHIFT, vector, vcount);
	tracecmd_append_options(handle);
#ifdef TSYNC_DEBUG
	if (count > 1)
		printf("Got %d timestamp synch samples for guest %s in %lld ns trace\n\r",
			count, tracefs_instance_get_name(instance->tracefs),
			ts[count - 1] - ts[0]);
#endif
out:
	if (handle)
		tracecmd_output_close(handle);
	else if (fd >= 0)
		close(fd);
	free(vector);
}

void tracecmd_host_tsync_complete(struct buffer_instance *instance)
{
	if (!instance->tsync_thread_running)
		return;

	/* Signal the time synchronization thread to complete and wait for it */
	pthread_mutex_lock(&instance->tsync.lock);
	pthread_cond_signal(&instance->tsync.cond);
	pthread_mutex_unlock(&instance->tsync.lock);
	pthread_join(instance->tsync_thread, NULL);
	write_guest_time_shift(instance);
	tracecmd_tsync_free(&instance->tsync);
}

static void *tsync_agent_thread(void *data)
{
	struct tracecmd_time_sync *tsync = NULL;
	int sd;

	tsync = (struct tracecmd_time_sync *)data;

	while (true) {
		sd = accept(tsync->msg_handle->fd, NULL, NULL);
		if (sd < 0) {
			if (errno == EINTR)
				continue;
			goto out;
		}
		break;
	}
	close(tsync->msg_handle->fd);
	tsync->msg_handle->fd = sd;

	tracecmd_tsync_with_host(tsync);

out:
	tracecmd_msg_handle_close(tsync->msg_handle);
	tracecmd_tsync_free(tsync);
	free(tsync);
	close(sd);

	pthread_exit(0);
}

const char *tracecmd_guest_tsync(struct tracecmd_tsync_protos *tsync_protos,
				 char *clock, unsigned int *tsync_port,
				 pthread_t *thr_id)
{
	struct tracecmd_time_sync *tsync = NULL;
	cpu_set_t *pin_mask = NULL;
	pthread_attr_t attrib;
	size_t mask_size = 0;
	const char *proto;
	int ret;
	int fd;

	fd = -1;
	proto = tracecmd_tsync_proto_select(tsync_protos, clock,
					    TRACECMD_TIME_SYNC_ROLE_GUEST);
	if (!proto)
		return NULL;
#ifdef VSOCK
	fd = trace_make_vsock(VMADDR_PORT_ANY);
	if (fd < 0)
		goto error;

	ret = trace_get_vsock_port(fd, tsync_port);
	if (ret < 0)
		goto error;
#else
	return NULL;
#endif

	tsync = calloc(1, sizeof(struct tracecmd_time_sync));
	tsync->msg_handle = tracecmd_msg_handle_alloc(fd, 0);
	if (clock)
		tsync->clock_str = strdup(clock);

	pthread_attr_init(&attrib);
	tsync->proto_name = proto;
	tsync->vcpu_count = tracecmd_count_cpus();
	pthread_attr_setdetachstate(&attrib, PTHREAD_CREATE_JOINABLE);

	ret = pthread_create(thr_id, &attrib, tsync_agent_thread, tsync);

	if (!ret) {
		if (!get_first_cpu(&pin_mask, &mask_size))
			pthread_setaffinity_np(*thr_id, mask_size, pin_mask);
	}

	if (pin_mask)
		CPU_FREE(pin_mask);
	pthread_attr_destroy(&attrib);

	if (ret)
		goto error;

	return proto;

error:
	if (tsync) {
		if (tsync->msg_handle)
			tracecmd_msg_handle_close(tsync->msg_handle);
		free(tsync->clock_str);
		free(tsync);
	}
	if (fd > 0)
		close(fd);
	return NULL;
}
