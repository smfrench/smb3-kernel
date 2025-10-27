/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (c) 2025 Stefan Metzmacher
 */

#ifndef __FS_SMB_COMMON_SMBDIRECT_SMBDIRECT_PRIVATE_H__
#define __FS_SMB_COMMON_SMBDIRECT_SMBDIRECT_PRIVATE_H__

#include <rdma/rw.h>

#ifdef SMBDIRECT_USE_INLINE_C_FILES
/* this is temporary while this file is included in others */
#define __SMBDIRECT_PRIVATE__ __maybe_unused static
#else
#define __SMBDIRECT_PRIVATE__
#endif

__SMBDIRECT_PRIVATE__
int smbdirect_socket_init_new(struct net *net, struct smbdirect_socket *sc);

__SMBDIRECT_PRIVATE__
void smbdirect_connection_rdma_established(struct smbdirect_socket *sc);

__SMBDIRECT_PRIVATE__
void smbdirect_connection_negotiation_done(struct smbdirect_socket *sc);

__SMBDIRECT_PRIVATE__
int smbdirect_connection_create_qp(struct smbdirect_socket *sc);

__SMBDIRECT_PRIVATE__
void smbdirect_connection_destroy_qp(struct smbdirect_socket *sc);

__SMBDIRECT_PRIVATE__
int smbdirect_connection_create_mem_pools(struct smbdirect_socket *sc);

__SMBDIRECT_PRIVATE__
void smbdirect_connection_destroy_mem_pools(struct smbdirect_socket *sc);

__SMBDIRECT_PRIVATE__
struct smbdirect_send_io *smbdirect_connection_alloc_send_io(struct smbdirect_socket *sc);

__SMBDIRECT_PRIVATE__
void smbdirect_connection_free_send_io(struct smbdirect_send_io *msg);

__SMBDIRECT_PRIVATE__
struct smbdirect_recv_io *smbdirect_connection_get_recv_io(struct smbdirect_socket *sc);

__SMBDIRECT_PRIVATE__
void smbdirect_connection_put_recv_io(struct smbdirect_recv_io *msg);

__SMBDIRECT_PRIVATE__
void smbdirect_connection_negotiate_rdma_resources(struct smbdirect_socket *sc,
						   u8 peer_initiator_depth,
						   u8 peer_responder_resources,
						   const struct rdma_conn_param *param);

__SMBDIRECT_PRIVATE__
void smbdirect_connection_schedule_disconnect(struct smbdirect_socket *sc,
					      int error);

__SMBDIRECT_PRIVATE__
void smbdirect_connection_destroy_sync(struct smbdirect_socket *sc);

__SMBDIRECT_PRIVATE__
void smbdirect_connection_idle_timer_work(struct work_struct *work);

__SMBDIRECT_PRIVATE__
int smbdirect_connection_wait_for_credits(struct smbdirect_socket *sc,
					  wait_queue_head_t *waitq,
					  atomic_t *total_credits,
					  int needed);

__SMBDIRECT_PRIVATE__
int smbdirect_connection_post_send_wr(struct smbdirect_socket *sc,
				      struct ib_send_wr *wr);

__SMBDIRECT_PRIVATE__
int smbdirect_connection_post_recv_io(struct smbdirect_recv_io *msg);

__SMBDIRECT_PRIVATE__
void smbdirect_connection_recv_io_done(struct ib_cq *cq, struct ib_wc *wc);

__SMBDIRECT_PRIVATE__
int smbdirect_connection_recv_io_refill(struct smbdirect_socket *sc);

__SMBDIRECT_PRIVATE__
int smbdirect_connection_create_mr_list(struct smbdirect_socket *sc);

__SMBDIRECT_PRIVATE__
void smbdirect_connection_destroy_mr_list(struct smbdirect_socket *sc);

#endif /* __FS_SMB_COMMON_SMBDIRECT_SMBDIRECT_PRIVATE_H__ */
