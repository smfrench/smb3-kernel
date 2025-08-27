// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2017, Microsoft Corporation.
 *   Copyright (c) 2025, Stefan Metzmacher
 */

#include "smbdirect_internal.h"

static void smbdirect_connection_schedule_disconnect(struct smbdirect_socket *sc,
						     int error);
static void smbdirect_connection_disconnect_work(struct work_struct *work);

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
