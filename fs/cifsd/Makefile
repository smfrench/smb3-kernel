# SPDX-License-Identifier: GPL-2.0-or-later
#
# Makefile for Linux SMB3 kernel server
#
obj-$(CONFIG_SMB_SERVER) += ksmbd.o

ksmbd-y :=	unicode.o auth.o vfs.o vfs_cache.o \
		misc.o oplock.o netmisc.o \
		mgmt/ksmbd_ida.o mgmt/user_config.o mgmt/share_config.o \
		mgmt/tree_connect.o mgmt/user_session.o smb_common.o \
		buffer_pool.o transport_tcp.o transport_ipc.o server.o \
		connection.o crypto_ctx.o ksmbd_work.o smbacl.o

ksmbd-y +=	smb2pdu.o smb2ops.o smb2misc.o asn1.o
ksmbd-$(CONFIG_SMB_SERVER_SMBDIRECT) += transport_rdma.o
