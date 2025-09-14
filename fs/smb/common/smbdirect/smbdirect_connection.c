// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2017, Microsoft Corporation.
 *   Copyright (c) 2025, Stefan Metzmacher
 */

#include "smbdirect_internal.h"
#include <linux/folio_queue.h>

struct smbdirect_map_sges {
	struct ib_sge *sge;
	size_t num_sge;
	size_t max_sge;
	struct ib_device *device;
	u32 local_dma_lkey;
	enum dma_data_direction direction;
};

static ssize_t smbdirect_map_sges_from_iter(struct iov_iter *iter, size_t len,
					    struct smbdirect_map_sges *state);

static void smbdirect_connection_schedule_disconnect(struct smbdirect_socket *sc,
						     int error);
static void smbdirect_connection_disconnect_work(struct work_struct *work);
static void smbdirect_connection_idle_timer_work(struct work_struct *work);

__maybe_unused /* this is temporary while this file is included in orders */
static bool smbdirect_frwr_is_supported(const struct ib_device_attr *attrs)
{
	/*
	 * Test if FRWR (Fast Registration Work Requests) is supported on the
	 * device This implementation requires FRWR on RDMA read/write return
	 * value: true if it is supported
	 */

	if (!(attrs->device_cap_flags & IB_DEVICE_MEM_MGT_EXTENSIONS))
		return false;
	if (attrs->max_fast_reg_page_list_len == 0)
		return false;
	return true;
}

__maybe_unused /* this is temporary while this file is included in orders */
static void smbdirect_socket_prepare_create(struct smbdirect_socket *sc,
					    const struct smbdirect_socket_parameters *sp,
					    struct workqueue_struct *workqueue)
{
	smbdirect_socket_init(sc);

	/*
	 * Make a copy of the callers parameters
	 * from here we only work on the copy
	 */
	sc->parameters = *sp;

	/*
	 * Remember the callers workqueue
	 */
	sc->workqueue = workqueue;

	INIT_WORK(&sc->disconnect_work, smbdirect_connection_disconnect_work);

	INIT_DELAYED_WORK(&sc->idle.timer_work, smbdirect_connection_idle_timer_work);
}

__maybe_unused /* this is temporary while this file is included in orders */
static void smbdirect_socket_set_logging(struct smbdirect_socket *sc,
					 void *private_ptr,
					 bool (*needed)(struct smbdirect_socket *sc,
							void *private_ptr,
							unsigned int lvl,
							unsigned int cls),
					 void (*vaprintf)(struct smbdirect_socket *sc,
							  const char *func,
							  unsigned int line,
							  void *private_ptr,
							  unsigned int lvl,
							  unsigned int cls,
							  struct va_format *vaf))
{
	sc->logging.private_ptr = private_ptr;
	sc->logging.needed = needed;
	sc->logging.vaprintf = vaprintf;
}

__maybe_unused /* this is temporary while this file is included in orders */
static void smbdirect_connection_wake_up_all(struct smbdirect_socket *sc)
{
	/*
	 * Wake up all waiters in all wait queues
	 * in order to notice the broken connection.
	 */
	wake_up_all(&sc->status_wait);
	wake_up_all(&sc->send_io.lcredits.wait_queue);
	wake_up_all(&sc->send_io.credits.wait_queue);
	wake_up_all(&sc->send_io.pending.dec_wait_queue);
	wake_up_all(&sc->send_io.pending.zero_wait_queue);
	wake_up_all(&sc->recv_io.reassembly.wait_queue);
	wake_up_all(&sc->rw_io.credits.wait_queue);
	wake_up_all(&sc->mr_io.ready.wait_queue);
	wake_up_all(&sc->mr_io.cleanup.wait_queue);
}

static void smbdirect_connection_destroy_mem_pools(struct smbdirect_socket *sc);

__maybe_unused /* this is temporary while this file is included in orders */
static int smbdirect_connection_create_mem_pools(struct smbdirect_socket *sc)
{
	struct smbdirect_socket_parameters *sp = &sc->parameters;
	char name[80];
	size_t i;

	/*
	 * We use sizeof(struct smbdirect_negotiate_resp) for the
	 * payload size as it is larger as
	 * sizeof(struct smbdirect_data_transfer).
	 *
	 * This will fit client and server usage for now.
	 */
	snprintf(name, sizeof(name), "smbdirect_send_io_cache_%p", sc);
	struct kmem_cache_args send_io_args = {
		.align		= __alignof__(struct smbdirect_send_io),
	};
	sc->send_io.mem.cache = kmem_cache_create(name,
						  sizeof(struct smbdirect_send_io) +
						  sizeof(struct smbdirect_negotiate_resp),
						  &send_io_args,
						  SLAB_HWCACHE_ALIGN);
	if (!sc->send_io.mem.cache)
		goto err;

	sc->send_io.mem.pool = mempool_create_slab_pool(sp->send_credit_target,
							sc->send_io.mem.cache);
	if (!sc->send_io.mem.pool)
		goto err;

	/*
	 * A payload size of sp->max_recv_size should fit
	 * any message.
	 *
	 * For smbdirect_data_transfer messages the whole
	 * buffer might be exposed to userspace
	 * (currently on the client side...)
	 * The documentation says data_offset = 0 would be
	 * strange but valid.
	 */
	snprintf(name, sizeof(name), "smbdirect_recv_io_cache_%p", sc);
	struct kmem_cache_args recv_io_args = {
		.align		= __alignof__(struct smbdirect_recv_io),
		.useroffset	= sizeof(struct smbdirect_recv_io),
		.usersize	= sp->max_recv_size,
	};
	sc->recv_io.mem.cache = kmem_cache_create(name,
						  sizeof(struct smbdirect_recv_io) +
						  sp->max_recv_size,
						  &recv_io_args,
						  SLAB_HWCACHE_ALIGN);
	if (!sc->recv_io.mem.cache)
		goto err;

	sc->recv_io.mem.pool = mempool_create_slab_pool(sp->recv_credit_max,
							sc->recv_io.mem.cache);
	if (!sc->recv_io.mem.pool)
		goto err;

	for (i = 0; i < sp->recv_credit_max; i++) {
		struct smbdirect_recv_io *recv_io;

		recv_io = mempool_alloc(sc->recv_io.mem.pool,
					sc->recv_io.mem.gfp_mask);
		if (!recv_io)
			goto err;
		recv_io->socket = sc;
		recv_io->sge.length = 0;
		INIT_WORK(&recv_io->complex_work, __smbdirect_socket_disabled_work);
		disable_work_sync(&recv_io->complex_work);
		list_add_tail(&recv_io->list, &sc->recv_io.free.list);
	}

	return 0;
err:
	smbdirect_connection_destroy_mem_pools(sc);
	return -ENOMEM;
}

static void smbdirect_connection_destroy_mem_pools(struct smbdirect_socket *sc)
{
	struct smbdirect_recv_io *recv_io, *next_io;

	list_for_each_entry_safe(recv_io, next_io, &sc->recv_io.free.list, list) {
		/*
		 * The work should already be disabled
		 */
		disable_work_sync(&recv_io->complex_work);
		list_del(&recv_io->list);
		mempool_free(recv_io, sc->recv_io.mem.pool);
	}

	/*
	 * Note mempool_destroy() and kmem_cache_destroy()
	 * work fine with a NULL pointer
	 */

	mempool_destroy(sc->recv_io.mem.pool);
	sc->recv_io.mem.pool = NULL;

	kmem_cache_destroy(sc->recv_io.mem.cache);
	sc->recv_io.mem.cache = NULL;

	mempool_destroy(sc->send_io.mem.pool);
	sc->send_io.mem.pool = NULL;

	kmem_cache_destroy(sc->send_io.mem.cache);
	sc->send_io.mem.cache = NULL;
}

__maybe_unused /* this is temporary while this file is included in orders */
static struct smbdirect_send_io *smbdirect_connection_alloc_send_io(struct smbdirect_socket *sc)
{
	struct smbdirect_send_io *msg;

	msg = mempool_alloc(sc->send_io.mem.pool, sc->send_io.mem.gfp_mask);
	if (!msg)
		return ERR_PTR(-ENOMEM);
	msg->socket = sc;
	INIT_LIST_HEAD(&msg->sibling_list);
	msg->num_sge = 0;

	return msg;
}

__maybe_unused /* this is temporary while this file is included in orders */
static void smbdirect_connection_free_send_io(struct smbdirect_send_io *msg)
{
	struct smbdirect_socket *sc = msg->socket;
	size_t i;

	/*
	 * The list needs to be empty!
	 * The caller should take care of it.
	 */
	WARN_ON_ONCE(!list_empty(&msg->sibling_list));

	/*
	 * Note we call ib_dma_unmap_page(), even if some sges are mapped using
	 * ib_dma_map_single().
	 *
	 * The difference between _single() and _page() only matters for the
	 * ib_dma_map_*() case.
	 *
	 * For the ib_dma_unmap_*() case it does not matter as both take the
	 * dma_addr_t and dma_unmap_single_attrs() is just an alias to
	 * dma_unmap_page_attrs().
	 */
	for (i = 0; i < msg->num_sge; i++)
		ib_dma_unmap_page(sc->ib.dev,
				  msg->sge[i].addr,
				  msg->sge[i].length,
				  DMA_TO_DEVICE);

	mempool_free(msg, sc->send_io.mem.pool);
}

__maybe_unused /* this is temporary while this file is included in orders */
static struct smbdirect_recv_io *smbdirect_connection_get_recv_io(struct smbdirect_socket *sc)
{
	struct smbdirect_recv_io *msg = NULL;
	unsigned long flags;

	spin_lock_irqsave(&sc->recv_io.free.lock, flags);
	if (likely(!sc->first_error))
		msg = list_first_entry_or_null(&sc->recv_io.free.list,
					       struct smbdirect_recv_io,
					       list);
	if (likely(msg)) {
		list_del(&msg->list);
		sc->statistics.get_receive_buffer++;
	}
	spin_unlock_irqrestore(&sc->recv_io.free.lock, flags);

	return msg;
}

__maybe_unused /* this is temporary while this file is included in orders */
static void smbdirect_connection_put_recv_io(struct smbdirect_recv_io *msg)
{
	struct smbdirect_socket *sc = msg->socket;
	unsigned long flags;

	/*
	 * Should already be disabled anyway.
	 */
	disable_work(&msg->complex_work);

	if (likely(msg->sge.length != 0)) {
		ib_dma_unmap_single(sc->ib.dev,
				    msg->sge.addr,
				    msg->sge.length,
				    DMA_FROM_DEVICE);
		msg->sge.length = 0;
	}

	spin_lock_irqsave(&sc->recv_io.free.lock, flags);
	list_add_tail(&msg->list, &sc->recv_io.free.list);
	sc->statistics.put_receive_buffer++;
	spin_unlock_irqrestore(&sc->recv_io.free.lock, flags);

	queue_work(sc->workqueue, &sc->recv_io.posted.refill_work);
}

__maybe_unused /* this is temporary while this file is included in orders */
static void smbdirect_connection_reassembly_append_recv_io(struct smbdirect_socket *sc,
							   struct smbdirect_recv_io *msg,
							   u32 data_length)
{
	unsigned long flags;

	/*
	 * The work should already/still be disabled
	 */
	disable_work(&msg->complex_work);

	spin_lock_irqsave(&sc->recv_io.reassembly.lock, flags);
	list_add_tail(&msg->list, &sc->recv_io.reassembly.list);
	sc->recv_io.reassembly.queue_length++;
	/*
	 * Make sure reassembly_data_length is updated after list and
	 * reassembly_queue_length are updated. On the dequeue side
	 * reassembly_data_length is checked without a lock to determine
	 * if reassembly_queue_length and list is up to date
	 */
	virt_wmb();
	sc->recv_io.reassembly.data_length += data_length;
	spin_unlock_irqrestore(&sc->recv_io.reassembly.lock, flags);
	sc->statistics.enqueue_reassembly_queue++;
}

__maybe_unused /* this is temporary while this file is included in orders */
static struct smbdirect_recv_io *
smbdirect_connection_reassembly_first_recv_io(struct smbdirect_socket *sc)
{
	struct smbdirect_recv_io *msg;

	msg = list_first_entry_or_null(&sc->recv_io.reassembly.list,
				       struct smbdirect_recv_io,
				       list);

	return msg;
}

__maybe_unused /* this is temporary while this file is included in orders */
static void smbdirect_connection_schedule_disconnect(struct smbdirect_socket *sc,
						     int error)
{
	struct smbdirect_recv_io *recv_io, *recv_tmp;
	unsigned long flags;

	if (sc->first_error == 0)
		sc->first_error = error;
	if (sc->first_error == 0)
		sc->first_error = -ECONNABORTED;

	/*
	 * make sure other work (than disconnect_work)
	 * is not queued again but here we don't block and avoid
	 * disable[_delayed]_work_sync()
	 */
	disable_work(&sc->recv_io.posted.refill_work);
	disable_work(&sc->mr_io.recovery_work);
	disable_work(&sc->idle.immediate_work);
	sc->idle.keepalive = SMBDIRECT_KEEPALIVE_NONE;
	disable_delayed_work(&sc->idle.timer_work);

	/*
	 * If any complex work was scheduled we
	 * should disable it (only happens during
	 * negotiation)...
	 *
	 * Note that sc->first_error is set before,
	 * so any future smbdirect_connection_get_recv_io()
	 * will see it and return NULL.
	 */
	spin_lock_irqsave(&sc->recv_io.free.lock, flags);
	list_for_each_entry_safe(recv_io, recv_tmp, &sc->recv_io.free.list, list)
		disable_work(&recv_io->complex_work);
	spin_unlock_irqrestore(&sc->recv_io.free.lock, flags);

	switch (sc->status) {
	case SMBDIRECT_SOCKET_RESOLVE_ADDR_FAILED:
	case SMBDIRECT_SOCKET_RESOLVE_ROUTE_FAILED:
	case SMBDIRECT_SOCKET_RDMA_CONNECT_FAILED:
	case SMBDIRECT_SOCKET_NEGOTIATE_FAILED:
	case SMBDIRECT_SOCKET_ERROR:
	case SMBDIRECT_SOCKET_DISCONNECTING:
	case SMBDIRECT_SOCKET_DISCONNECTED:
	case SMBDIRECT_SOCKET_DESTROYED:
		/*
		 * Keep the current error status
		 */
		break;

	case SMBDIRECT_SOCKET_RESOLVE_ADDR_NEEDED:
	case SMBDIRECT_SOCKET_RESOLVE_ADDR_RUNNING:
		sc->status = SMBDIRECT_SOCKET_RESOLVE_ADDR_FAILED;
		break;

	case SMBDIRECT_SOCKET_RESOLVE_ROUTE_NEEDED:
	case SMBDIRECT_SOCKET_RESOLVE_ROUTE_RUNNING:
		sc->status = SMBDIRECT_SOCKET_RESOLVE_ROUTE_FAILED;
		break;

	case SMBDIRECT_SOCKET_RDMA_CONNECT_NEEDED:
	case SMBDIRECT_SOCKET_RDMA_CONNECT_RUNNING:
		sc->status = SMBDIRECT_SOCKET_RDMA_CONNECT_FAILED;
		break;

	case SMBDIRECT_SOCKET_NEGOTIATE_NEEDED:
	case SMBDIRECT_SOCKET_NEGOTIATE_RUNNING:
		sc->status = SMBDIRECT_SOCKET_NEGOTIATE_FAILED;
		break;

	case SMBDIRECT_SOCKET_CREATED:
	case SMBDIRECT_SOCKET_CONNECTED:
		sc->status = SMBDIRECT_SOCKET_ERROR;
		break;
	}

	/*
	 * Wake up all waiters in all wait queues
	 * in order to notice the broken connection.
	 */
	smbdirect_connection_wake_up_all(sc);

	queue_work(sc->workqueue, &sc->disconnect_work);
}

static void smbdirect_connection_disconnect_work(struct work_struct *work)
{
	struct smbdirect_socket *sc =
		container_of(work, struct smbdirect_socket, disconnect_work);
	struct smbdirect_recv_io *recv_io, *recv_tmp;
	unsigned long flags;

	/*
	 * This should not never be called in an interrupt!
	 */
	WARN_ON_ONCE(in_interrupt());

	if (sc->first_error == 0)
		sc->first_error = -ECONNABORTED;

	/*
	 * make sure this and other work is not queued again
	 * but here we don't block and avoid
	 * disable[_delayed]_work_sync()
	 */
	disable_work(&sc->disconnect_work);
	disable_work(&sc->recv_io.posted.refill_work);
	disable_work(&sc->mr_io.recovery_work);
	disable_work(&sc->idle.immediate_work);
	sc->idle.keepalive = SMBDIRECT_KEEPALIVE_NONE;
	disable_delayed_work(&sc->idle.timer_work);

	/*
	 * If any complex work was scheduled we
	 * should disable it (only happens during
	 * negotiation)...
	 *
	 * Note that sc->first_error is set before,
	 * so any future smbdirect_connection_get_recv_io()
	 * will see it and return NULL.
	 */
	spin_lock_irqsave(&sc->recv_io.free.lock, flags);
	list_for_each_entry_safe(recv_io, recv_tmp, &sc->recv_io.free.list, list)
		disable_work(&recv_io->complex_work);
	spin_unlock_irqrestore(&sc->recv_io.free.lock, flags);

	switch (sc->status) {
	case SMBDIRECT_SOCKET_NEGOTIATE_NEEDED:
	case SMBDIRECT_SOCKET_NEGOTIATE_RUNNING:
	case SMBDIRECT_SOCKET_NEGOTIATE_FAILED:
	case SMBDIRECT_SOCKET_CONNECTED:
	case SMBDIRECT_SOCKET_ERROR:
		sc->status = SMBDIRECT_SOCKET_DISCONNECTING;
		rdma_disconnect(sc->rdma.cm_id);
		break;

	case SMBDIRECT_SOCKET_CREATED:
	case SMBDIRECT_SOCKET_RESOLVE_ADDR_NEEDED:
	case SMBDIRECT_SOCKET_RESOLVE_ADDR_RUNNING:
	case SMBDIRECT_SOCKET_RESOLVE_ADDR_FAILED:
	case SMBDIRECT_SOCKET_RESOLVE_ROUTE_NEEDED:
	case SMBDIRECT_SOCKET_RESOLVE_ROUTE_RUNNING:
	case SMBDIRECT_SOCKET_RESOLVE_ROUTE_FAILED:
	case SMBDIRECT_SOCKET_RDMA_CONNECT_NEEDED:
	case SMBDIRECT_SOCKET_RDMA_CONNECT_RUNNING:
	case SMBDIRECT_SOCKET_RDMA_CONNECT_FAILED:
		/*
		 * rdma_{accept,connect}() never reached
		 * RDMA_CM_EVENT_ESTABLISHED
		 */
		sc->status = SMBDIRECT_SOCKET_DISCONNECTED;
		break;

	case SMBDIRECT_SOCKET_DISCONNECTING:
	case SMBDIRECT_SOCKET_DISCONNECTED:
	case SMBDIRECT_SOCKET_DESTROYED:
		break;
	}

	/*
	 * Wake up all waiters in all wait queues
	 * in order to notice the broken connection.
	 */
	smbdirect_connection_wake_up_all(sc);
}

static void smbdirect_connection_idle_timer_work(struct work_struct *work)
{
	struct smbdirect_socket *sc =
		container_of(work, struct smbdirect_socket, idle.timer_work.work);
	const struct smbdirect_socket_parameters *sp = &sc->parameters;

	if (sc->idle.keepalive != SMBDIRECT_KEEPALIVE_NONE) {
		smbdirect_log_keep_alive(sc, SMBDIRECT_LOG_ERR,
			"%s => timeout sc->idle.keepalive=%s\n",
			smbdirect_socket_status_string(sc->status),
			sc->idle.keepalive == SMBDIRECT_KEEPALIVE_SENT ?
			"SENT" : "PENDING");
		smbdirect_connection_schedule_disconnect(sc, -ETIMEDOUT);
		return;
	}

	if (sc->status != SMBDIRECT_SOCKET_CONNECTED)
		return;

	/*
	 * Now use the keepalive timeout (instead of keepalive interval)
	 * in order to wait for a response
	 */
	sc->idle.keepalive = SMBDIRECT_KEEPALIVE_PENDING;
	mod_delayed_work(sc->workqueue, &sc->idle.timer_work,
			 msecs_to_jiffies(sp->keepalive_timeout_msec));
	smbdirect_log_keep_alive(sc, SMBDIRECT_LOG_INFO,
		"schedule send of empty idle message\n");
	queue_work(sc->workqueue, &sc->idle.immediate_work);
}

__maybe_unused /* this is temporary while this file is included in orders */
static void smbdirect_connection_send_io_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct smbdirect_send_io *msg =
		container_of(wc->wr_cqe, struct smbdirect_send_io, cqe);
	struct smbdirect_socket *sc = msg->socket;
	struct smbdirect_send_io *sibling, *next;
	int lcredits = 0;

	smbdirect_log_rdma_send(sc, SMBDIRECT_LOG_INFO,
		"smbdirect_send_io completed. status='%s (%d)', opcode=%d\n",
		ib_wc_status_msg(wc->status), wc->status, wc->opcode);

	/*
	 * Free possible siblings and then the main send_io
	 */
	list_for_each_entry_safe(sibling, next, &msg->sibling_list, sibling_list) {
		list_del_init(&sibling->sibling_list);
		smbdirect_connection_free_send_io(sibling);
		lcredits += 1;
	}
	/* Note this frees wc->wr_cqe, but not wc */
	smbdirect_connection_free_send_io(msg);
	lcredits += 1;

	if (unlikely(wc->status != IB_WC_SUCCESS || WARN_ON_ONCE(wc->opcode != IB_WC_SEND))) {
		if (wc->status != IB_WC_WR_FLUSH_ERR)
			smbdirect_log_rdma_send(sc, SMBDIRECT_LOG_ERR,
				"wc->status=%s (%d) wc->opcode=%d\n",
				ib_wc_status_msg(wc->status), wc->status, wc->opcode);
		smbdirect_connection_schedule_disconnect(sc, -ECONNABORTED);
		return;
	}

	atomic_add(lcredits, &sc->send_io.lcredits.count);
	wake_up(&sc->send_io.lcredits.wait_queue);

	if (atomic_dec_and_test(&sc->send_io.pending.count))
		wake_up(&sc->send_io.pending.zero_wait_queue);

	wake_up(&sc->send_io.pending.dec_wait_queue);
}

static bool smbdirect_map_sges_single_page(struct smbdirect_map_sges *state,
					   struct page *page, size_t off, size_t len)
{
	struct ib_sge *sge;
	u64 addr;

	if (state->num_sge >= state->max_sge)
		return false;

	addr = ib_dma_map_page(state->device, page,
			       off, len, state->direction);
	if (ib_dma_mapping_error(state->device, addr))
		return false;

	sge = &state->sge[state->num_sge++];
	sge->addr   = addr;
	sge->length = len;
	sge->lkey   = state->local_dma_lkey;

	return true;
}

/*
 * Extract page fragments from a BVEC-class iterator and add them to an ib_sge
 * list.  The pages are not pinned.
 */
static ssize_t smbdirect_map_sges_from_bvec(struct iov_iter *iter,
					    struct smbdirect_map_sges *state,
					    ssize_t maxsize)
{
	const struct bio_vec *bv = iter->bvec;
	unsigned long start = iter->iov_offset;
	unsigned int i;
	ssize_t ret = 0;

	for (i = 0; i < iter->nr_segs; i++) {
		size_t off, len;
		bool ok;

		len = bv[i].bv_len;
		if (start >= len) {
			start -= len;
			continue;
		}

		len = min_t(size_t, maxsize, len - start);
		off = bv[i].bv_offset + start;

		ok = smbdirect_map_sges_single_page(state,
						    bv[i].bv_page,
						    off,
						    len);
		if (!ok)
			return -EIO;

		ret += len;
		maxsize -= len;
		if (state->num_sge >= state->max_sge || maxsize <= 0)
			break;
		start = 0;
	}

	if (ret > 0)
		iov_iter_advance(iter, ret);
	return ret;
}

/*
 * Extract fragments from a KVEC-class iterator and add them to an ib_sge list.
 * This can deal with vmalloc'd buffers as well as kmalloc'd or static buffers.
 * The pages are not pinned.
 */
static ssize_t smbdirect_map_sges_from_kvec(struct iov_iter *iter,
					    struct smbdirect_map_sges *state,
					    ssize_t maxsize)
{
	const struct kvec *kv = iter->kvec;
	unsigned long start = iter->iov_offset;
	unsigned int i;
	ssize_t ret = 0;

	for (i = 0; i < iter->nr_segs; i++) {
		struct page *page;
		unsigned long kaddr;
		size_t off, len, seg;

		len = kv[i].iov_len;
		if (start >= len) {
			start -= len;
			continue;
		}

		kaddr = (unsigned long)kv[i].iov_base + start;
		off = kaddr & ~PAGE_MASK;
		len = min_t(size_t, maxsize, len - start);
		kaddr &= PAGE_MASK;

		maxsize -= len;
		do {
			bool ok;

			seg = min_t(size_t, len, PAGE_SIZE - off);

			if (is_vmalloc_or_module_addr((void *)kaddr))
				page = vmalloc_to_page((void *)kaddr);
			else
				page = virt_to_page((void *)kaddr);

			ok = smbdirect_map_sges_single_page(state, page, off, seg);
			if (!ok)
				return -EIO;

			ret += seg;
			len -= seg;
			kaddr += PAGE_SIZE;
			off = 0;
		} while (len > 0 && state->num_sge < state->max_sge);

		if (state->num_sge >= state->max_sge || maxsize <= 0)
			break;
		start = 0;
	}

	if (ret > 0)
		iov_iter_advance(iter, ret);
	return ret;
}

/*
 * Extract folio fragments from a FOLIOQ-class iterator and add them to an
 * ib_sge list.  The folios are not pinned.
 */
static ssize_t smbdirect_map_sges_from_folioq(struct iov_iter *iter,
					      struct smbdirect_map_sges *state,
					      ssize_t maxsize)
{
	const struct folio_queue *folioq = iter->folioq;
	unsigned int slot = iter->folioq_slot;
	ssize_t ret = 0;
	size_t offset = iter->iov_offset;

	if (WARN_ON_ONCE(!folioq))
		return -EIO;

	if (slot >= folioq_nr_slots(folioq)) {
		folioq = folioq->next;
		if (WARN_ON_ONCE(!folioq))
			return -EIO;
		slot = 0;
	}

	do {
		struct folio *folio = folioq_folio(folioq, slot);
		size_t fsize = folioq_folio_size(folioq, slot);

		if (offset < fsize) {
			size_t part = umin(maxsize, fsize - offset);
			bool ok;

			ok = smbdirect_map_sges_single_page(state,
							    folio_page(folio, 0),
							    offset,
							    part);
			if (!ok)
				return -EIO;

			offset += part;
			ret += part;
			maxsize -= part;
		}

		if (offset >= fsize) {
			offset = 0;
			slot++;
			if (slot >= folioq_nr_slots(folioq)) {
				if (!folioq->next) {
					WARN_ON_ONCE(ret < iter->count);
					break;
				}
				folioq = folioq->next;
				slot = 0;
			}
		}
	} while (state->num_sge < state->max_sge && maxsize > 0);

	iter->folioq = folioq;
	iter->folioq_slot = slot;
	iter->iov_offset = offset;
	iter->count -= ret;
	return ret;
}

/*
 * Extract page fragments from up to the given amount of the source iterator
 * and build up an ib_sge list that refers to all of those bits.  The ib_sge list
 * is appended to, up to the maximum number of elements set in the parameter
 * block.
 *
 * The extracted page fragments are not pinned or ref'd in any way; if an
 * IOVEC/UBUF-type iterator is to be used, it should be converted to a
 * BVEC-type iterator and the pages pinned, ref'd or otherwise held in some
 * way.
 */
__maybe_unused /* this is temporary while this file is included in orders */
static ssize_t smbdirect_map_sges_from_iter(struct iov_iter *iter, size_t len,
					    struct smbdirect_map_sges *state)
{
	ssize_t ret;
	size_t before = state->num_sge;

	if (WARN_ON_ONCE(iov_iter_rw(iter) != ITER_SOURCE))
		return -EIO;

	switch (iov_iter_type(iter)) {
	case ITER_BVEC:
		ret = smbdirect_map_sges_from_bvec(iter, state, len);
		break;
	case ITER_KVEC:
		ret = smbdirect_map_sges_from_kvec(iter, state, len);
		break;
	case ITER_FOLIOQ:
		ret = smbdirect_map_sges_from_folioq(iter, state, len);
		break;
	default:
		WARN_ON_ONCE(1);
		return -EIO;
	}

	if (ret < 0) {
		while (state->num_sge > before) {
			struct ib_sge *sge = &state->sge[state->num_sge--];

			ib_dma_unmap_page(state->device,
					  sge->addr,
					  sge->length,
					  state->direction);
		}
	}

	return ret;
}
