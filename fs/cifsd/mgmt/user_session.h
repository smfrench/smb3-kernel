/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#ifndef __USER_SESSION_MANAGEMENT_H__
#define __USER_SESSION_MANAGEMENT_H__

#include <linux/hashtable.h>

#include "../smb_common.h"
#include "../ntlmssp.h"

#define CIFDS_SESSION_FLAG_SMB1		(1 << 0)
#define CIFDS_SESSION_FLAG_SMB2		(1 << 1)

#define PREAUTH_HASHVALUE_SIZE		64

struct ksmbd_ida;
struct ksmbd_file_table;

struct channel {
	__u8			smb3signingkey[SMB3_SIGN_KEY_SIZE];
	struct ksmbd_conn	*conn;
	struct list_head	chann_list;
};

struct preauth_session {
	__u8			Preauth_HashValue[PREAUTH_HASHVALUE_SIZE];
	uint64_t		sess_id;
	struct list_head	list_entry;
};

struct ksmbd_session {
	uint64_t			id;

	struct ksmbd_user		*user;
	struct ksmbd_conn		*conn;
	unsigned int			sequence_number;
	unsigned int			flags;

	bool				sign;
	bool				enc;
	bool				is_anonymous;

	int				state;
	__u8				*Preauth_HashValue;

	struct ntlmssp_auth		ntlmssp;
	char				sess_key[CIFS_KEY_SIZE];

	struct hlist_node		hlist;
	struct list_head		ksmbd_chann_list;
	struct list_head		tree_conn_list;
	struct ksmbd_ida		*tree_conn_ida;
	struct list_head		rpc_handle_list;

	__u8				smb3encryptionkey[SMB3_SIGN_KEY_SIZE];
	__u8				smb3decryptionkey[SMB3_SIGN_KEY_SIZE];
	__u8				smb3signingkey[SMB3_SIGN_KEY_SIZE];

	struct list_head		sessions_entry;
	struct ksmbd_file_table		file_table;
};

static inline int test_session_flag(struct ksmbd_session *sess, int bit)
{
	return sess->flags & bit;
}

static inline void set_session_flag(struct ksmbd_session *sess, int bit)
{
	sess->flags |= bit;
}

static inline void clear_session_flag(struct ksmbd_session *sess, int bit)
{
	sess->flags &= ~bit;
}

struct ksmbd_session *ksmbd_smb2_session_create(void);

void ksmbd_session_destroy(struct ksmbd_session *sess);

bool ksmbd_session_id_match(struct ksmbd_session *sess, unsigned long long id);
struct ksmbd_session *ksmbd_session_lookup_slowpath(unsigned long long id);
struct ksmbd_session *ksmbd_session_lookup(struct ksmbd_conn *conn,
					   unsigned long long id);
void ksmbd_session_register(struct ksmbd_conn *conn,
			    struct ksmbd_session *sess);
void ksmbd_sessions_deregister(struct ksmbd_conn *conn);

int ksmbd_acquire_tree_conn_id(struct ksmbd_session *sess);
void ksmbd_release_tree_conn_id(struct ksmbd_session *sess, int id);

int ksmbd_session_rpc_open(struct ksmbd_session *sess, char *rpc_name);
void ksmbd_session_rpc_close(struct ksmbd_session *sess, int id);
int ksmbd_session_rpc_method(struct ksmbd_session *sess, int id);

int ksmbd_init_session_table(void);
void ksmbd_free_session_table(void);

#endif /* __USER_SESSION_MANAGEMENT_H__ */
