// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/backing-dev.h>
#include <linux/writeback.h>
#include <linux/version.h>
#include <linux/xattr.h>
#include <linux/falloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/fsnotify.h>
#include <linux/dcache.h>
#include <linux/fiemap.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/sched/xacct.h>

#include "glob.h"
#include "oplock.h"
#include "connection.h"
#include "buffer_pool.h"
#include "vfs.h"
#include "vfs_cache.h"

#include "time_wrappers.h"
#include "smb_common.h"
#include "mgmt/share_config.h"
#include "mgmt/tree_connect.h"
#include "mgmt/user_session.h"
#include "mgmt/user_config.h"

static char *extract_last_component(char *path)
{
	char *p = strrchr(path, '/');

	if (p && p[1] != '\0') {
		*p = '\0';
		p++;
	} else {
		ksmbd_err("Invalid path %s\n", path);
	}
	return p;
}

static void roolback_path_modification(char *filename)
{
	if (filename) {
		filename--;
		*filename = '/';
	}
}

static void ksmbd_vfs_inherit_owner(struct ksmbd_work *work,
				    struct inode *parent_inode,
				    struct inode *inode)
{
	if (!test_share_config_flag(work->tcon->share_conf,
				   KSMBD_SHARE_FLAG_INHERIT_OWNER))
		return;

	i_uid_write(inode, i_uid_read(parent_inode));
}

static void ksmbd_vfs_inherit_smack(struct ksmbd_work *work,
				    struct dentry *dir_dentry,
				    struct dentry *dentry)
{
	char *name, *xattr_list = NULL, *smack_buf;
	int value_len, xattr_list_len;

	if (!test_share_config_flag(work->tcon->share_conf,
				    KSMBD_SHARE_FLAG_INHERIT_SMACK))
		return;

	xattr_list_len = ksmbd_vfs_listxattr(dir_dentry, &xattr_list);
	if (xattr_list_len < 0) {
		goto out;
	} else if (!xattr_list_len) {
		ksmbd_err("no ea data in the file\n");
		return;
	}

	for (name = xattr_list; name - xattr_list < xattr_list_len;
			name += strlen(name) + 1) {
		int rc;

		ksmbd_debug(VFS, "%s, len %zd\n", name, strlen(name));
		if (strcmp(name, XATTR_NAME_SMACK))
			continue;

		value_len = ksmbd_vfs_getxattr(dir_dentry, name, &smack_buf);
		if (value_len <= 0)
			continue;

		rc = ksmbd_vfs_setxattr(dentry, XATTR_NAME_SMACK, smack_buf,
					value_len, 0);
		ksmbd_free(smack_buf);
		if (rc < 0)
			ksmbd_err("ksmbd_vfs_setxattr() failed: %d\n", rc);
	}
out:
	ksmbd_vfs_xattr_free(xattr_list);
}

int ksmbd_vfs_inode_permission(struct dentry *dentry, int acc_mode, bool delete)
{
	int mask;

	mask = 0;
	acc_mode &= O_ACCMODE;

	if (acc_mode == O_RDONLY)
		mask = MAY_READ;
	else if (acc_mode == O_WRONLY)
		mask = MAY_WRITE;
	else if (acc_mode == O_RDWR)
		mask = MAY_READ | MAY_WRITE;

	if (inode_permission(d_inode(dentry), mask | MAY_OPEN))
		return -EACCES;

	if (delete) {
		struct dentry *parent;

		parent = dget_parent(dentry);
		if (!parent)
			return -EINVAL;

		if (inode_permission(d_inode(parent), MAY_EXEC | MAY_WRITE)) {
			dput(parent);
			return -EACCES;
		}
		dput(parent);
	}
	return 0;
}

/**
 * ksmbd_vfs_create() - vfs helper for smb create file
 * @work:	work
 * @name:	file name
 * @mode:	file create mode
 *
 * Return:	0 on success, otherwise error
 */
int ksmbd_vfs_create(struct ksmbd_work *work,
		     const char *name,
		     umode_t mode)
{
	struct path path;
	struct dentry *dentry;
	int err;

	dentry = kern_path_create(AT_FDCWD, name, &path, 0);
	if (IS_ERR(dentry)) {
		err = PTR_ERR(dentry);
		if (err != -ENOENT)
			ksmbd_err("path create failed for %s, err %d\n",
				name, err);
		return err;
	}

	mode |= S_IFREG;
	err = vfs_create(d_inode(path.dentry), dentry, mode, true);
	if (!err) {
		ksmbd_vfs_inherit_owner(work, d_inode(path.dentry),
			d_inode(dentry));
		ksmbd_vfs_inherit_smack(work, path.dentry, dentry);
	} else {
		ksmbd_err("File(%s): creation failed (err:%d)\n", name, err);
	}
	done_path_create(&path, dentry);
	return err;
}

/**
 * ksmbd_vfs_mkdir() - vfs helper for smb create directory
 * @work:	work
 * @name:	directory name
 * @mode:	directory create mode
 *
 * Return:	0 on success, otherwise error
 */
int ksmbd_vfs_mkdir(struct ksmbd_work *work,
		    const char *name,
		    umode_t mode)
{
	struct path path;
	struct dentry *dentry;
	int err;

	if (ksmbd_override_fsids(work))
		return -ENOMEM;

	dentry = kern_path_create(AT_FDCWD, name, &path, LOOKUP_DIRECTORY);
	if (IS_ERR(dentry)) {
		ksmbd_revert_fsids(work);
		err = PTR_ERR(dentry);
		if (err != -EEXIST)
			ksmbd_debug(VFS, "path create failed for %s, err %d\n",
					name, err);
		return err;
	}

	mode |= S_IFDIR;
	err = vfs_mkdir(d_inode(path.dentry), dentry, mode);
	if (!err) {
		ksmbd_vfs_inherit_owner(work, d_inode(path.dentry),
			d_inode(dentry));
		ksmbd_vfs_inherit_smack(work, path.dentry, dentry);
	} else
		ksmbd_err("mkdir(%s): creation failed (err:%d)\n", name, err);

	done_path_create(&path, dentry);
	ksmbd_revert_fsids(work);
	return err;
}

static ssize_t ksmbd_vfs_getcasexattr(struct dentry *dentry,
				      char *attr_name,
				      int attr_name_len,
				      char **attr_value)
{
	char *name, *xattr_list = NULL;
	ssize_t value_len = -ENOENT, xattr_list_len;

	xattr_list_len = ksmbd_vfs_listxattr(dentry, &xattr_list);
	if (xattr_list_len <= 0)
		goto out;

	for (name = xattr_list; name - xattr_list < xattr_list_len;
			name += strlen(name) + 1) {
		ksmbd_debug(VFS, "%s, len %zd\n", name, strlen(name));
		if (strncasecmp(attr_name, name, attr_name_len))
			continue;

		value_len = ksmbd_vfs_getxattr(dentry,
					       name,
					       attr_value);
		if (value_len < 0)
			ksmbd_err("failed to get xattr in file\n");
		break;
	}

out:
	ksmbd_vfs_xattr_free(xattr_list);
	return value_len;
}

static int ksmbd_vfs_stream_read(struct ksmbd_file *fp, char *buf, loff_t *pos,
	size_t count)
{
	ssize_t v_len;
	char *stream_buf = NULL;
	int err;

	ksmbd_debug(VFS, "read stream data pos : %llu, count : %zd\n",
			*pos, count);

	v_len = ksmbd_vfs_getcasexattr(fp->filp->f_path.dentry,
				       fp->stream.name,
				       fp->stream.size,
				       &stream_buf);
	if (v_len == -ENOENT) {
		ksmbd_err("not found stream in xattr : %zd\n", v_len);
		err = -ENOENT;
		return err;
	}

	memcpy(buf, &stream_buf[*pos], count);
	return v_len > count ? count : v_len;
}

/**
 * check_lock_range() - vfs helper for smb byte range file locking
 * @filp:	the file to apply the lock to
 * @start:	lock start byte offset
 * @end:	lock end byte offset
 * @type:	byte range type read/write
 *
 * Return:	0 on success, otherwise error
 */
static int check_lock_range(struct file *filp,
			    loff_t start,
			    loff_t end,
			    unsigned char type)
{
	struct file_lock *flock;
	struct file_lock_context *ctx = file_inode(filp)->i_flctx;
	int error = 0;

	if (!ctx || list_empty_careful(&ctx->flc_posix))
		return 0;

	spin_lock(&ctx->flc_lock);
	list_for_each_entry(flock, &ctx->flc_posix, fl_list) {
		/* check conflict locks */
		if (flock->fl_end >= start && end >= flock->fl_start) {
			if (flock->fl_type == F_RDLCK) {
				if (type == WRITE) {
					ksmbd_err("not allow write by shared lock\n");
					error = 1;
					goto out;
				}
			} else if (flock->fl_type == F_WRLCK) {
				/* check owner in lock */
				if (flock->fl_file != filp) {
					error = 1;
					ksmbd_err("not allow rw access by exclusive lock from other opens\n");
					goto out;
				}
			}
		}
	}
out:
	spin_unlock(&ctx->flc_lock);
	return error;
}

/**
 * ksmbd_vfs_read() - vfs helper for smb file read
 * @work:	smb work
 * @fid:	file id of open file
 * @count:	read byte count
 * @pos:	file pos
 *
 * Return:	number of read bytes on success, otherwise error
 */
int ksmbd_vfs_read(struct ksmbd_work *work,
		 struct ksmbd_file *fp,
		 size_t count,
		 loff_t *pos)
{
	struct file *filp;
	ssize_t nbytes = 0;
	char *rbuf, *name;
	struct inode *inode;
	char namebuf[NAME_MAX];
	int ret;

	rbuf = AUX_PAYLOAD(work);
	filp = fp->filp;
	inode = d_inode(filp->f_path.dentry);
	if (S_ISDIR(inode->i_mode))
		return -EISDIR;

	if (unlikely(count == 0))
		return 0;

	if (work->conn->connection_type) {
		if (!(fp->daccess & (FILE_READ_DATA_LE |
		    FILE_GENERIC_READ_LE | FILE_MAXIMAL_ACCESS_LE |
		    FILE_GENERIC_ALL_LE | FILE_EXECUTE_LE))) {
			ksmbd_err("no right to read(%s)\n", FP_FILENAME(fp));
			return -EACCES;
		}
	}

	if (ksmbd_stream_fd(fp))
		return ksmbd_vfs_stream_read(fp, rbuf, pos, count);

	ret = check_lock_range(filp, *pos, *pos + count - 1,
			READ);
	if (ret) {
		ksmbd_err("unable to read due to lock\n");
		return -EAGAIN;
	}

	nbytes = kernel_read(filp, rbuf, count, pos);
	if (nbytes < 0) {
		name = d_path(&filp->f_path, namebuf, sizeof(namebuf));
		if (IS_ERR(name))
			name = "(error)";
		ksmbd_err("smb read failed for (%s), err = %zd\n",
				name, nbytes);
		return nbytes;
	}

	filp->f_pos = *pos;
	return nbytes;
}

static int ksmbd_vfs_stream_write(struct ksmbd_file *fp, char *buf, loff_t *pos,
	size_t count)
{
	char *stream_buf = NULL, *wbuf;
	size_t size, v_len;
	int err = 0;

	ksmbd_debug(VFS, "write stream data pos : %llu, count : %zd\n",
			*pos, count);

	size = *pos + count;
	if (size > XATTR_SIZE_MAX) {
		size = XATTR_SIZE_MAX;
		count = (*pos + count) - XATTR_SIZE_MAX;
	}

	v_len = ksmbd_vfs_getcasexattr(fp->filp->f_path.dentry,
				       fp->stream.name,
				       fp->stream.size,
				       &stream_buf);
	if (v_len == -ENOENT) {
		ksmbd_err("not found stream in xattr : %zd\n", v_len);
		err = -ENOENT;
		goto out;
	}

	if (v_len < size) {
		wbuf = ksmbd_alloc(size);
		if (!wbuf) {
			err = -ENOMEM;
			goto out;
		}

		if (v_len > 0)
			memcpy(wbuf, stream_buf, v_len);
		stream_buf = wbuf;
	}

	memcpy(&stream_buf[*pos], buf, count);

	err = ksmbd_vfs_setxattr(fp->filp->f_path.dentry,
				 fp->stream.name,
				 (void *)stream_buf,
				 size,
				 0);
	if (err < 0)
		goto out;

	fp->filp->f_pos = *pos;
	err = 0;
out:
	ksmbd_free(stream_buf);
	return err;
}

/**
 * ksmbd_vfs_write() - vfs helper for smb file write
 * @work:	work
 * @fid:	file id of open file
 * @buf:	buf containing data for writing
 * @count:	read byte count
 * @pos:	file pos
 * @sync:	fsync after write
 * @written:	number of bytes written
 *
 * Return:	0 on success, otherwise error
 */
int ksmbd_vfs_write(struct ksmbd_work *work, struct ksmbd_file *fp,
	char *buf, size_t count, loff_t *pos, bool sync, ssize_t *written)
{
	struct ksmbd_session *sess = work->sess;
	struct file *filp;
	loff_t	offset = *pos;
	int err = 0;

	if (sess->conn->connection_type) {
		if (!(fp->daccess & (FILE_WRITE_DATA_LE |
		   FILE_GENERIC_WRITE_LE | FILE_MAXIMAL_ACCESS_LE |
		   FILE_GENERIC_ALL_LE))) {
			ksmbd_err("no right to write(%s)\n", FP_FILENAME(fp));
			err = -EACCES;
			goto out;
		}
	}

	filp = fp->filp;

	if (ksmbd_stream_fd(fp)) {
		err = ksmbd_vfs_stream_write(fp, buf, pos, count);
		if (!err)
			*written = count;
		goto out;
	}

	err = check_lock_range(filp, *pos, *pos + count - 1, WRITE);
	if (err) {
		ksmbd_err("unable to write due to lock\n");
		err = -EAGAIN;
		goto out;
	}

	/* Do we need to break any of a levelII oplock? */
	smb_break_all_levII_oplock(work, fp, 1);

	err = kernel_write(filp, buf, count, pos);
	if (err < 0) {
		ksmbd_debug(VFS, "smb write failed, err = %d\n", err);
		goto out;
	}

	filp->f_pos = *pos;
	*written = err;
	err = 0;
	if (sync) {
		err = vfs_fsync_range(filp, offset, offset + *written, 0);
		if (err < 0)
			ksmbd_err("fsync failed for filename = %s, err = %d\n",
					FP_FILENAME(fp), err);
	}

out:
	return err;
}

static void __fill_dentry_attributes(struct ksmbd_work *work,
				     struct dentry *dentry,
				     struct ksmbd_kstat *ksmbd_kstat)
{
	/*
	 * set default value for the case that store dos attributes is not yes
	 * or that acl is disable in server's filesystem and the config is yes.
	 */
	if (S_ISDIR(ksmbd_kstat->kstat->mode))
		ksmbd_kstat->file_attributes = ATTR_DIRECTORY_LE;
	else
		ksmbd_kstat->file_attributes = ATTR_ARCHIVE_LE;

	if (test_share_config_flag(work->tcon->share_conf,
				   KSMBD_SHARE_FLAG_STORE_DOS_ATTRS)) {
		char *file_attribute = NULL;
		int rc;

		rc = ksmbd_vfs_getxattr(dentry,
					XATTR_NAME_FILE_ATTRIBUTE,
					&file_attribute);
		if (rc > 0)
			ksmbd_kstat->file_attributes =
				*((__le32 *)file_attribute);
		else
			ksmbd_debug(VFS, "fail to fill file attributes.\n");
		ksmbd_free(file_attribute);
	}
}

static void __file_dentry_ctime(struct ksmbd_work *work,
				struct dentry *dentry,
				struct ksmbd_kstat *ksmbd_kstat)
{
	char *create_time = NULL;
	int xattr_len;
	u64 time;

	/*
	 * if "store dos attributes" conf is not yes,
	 * create time = change time
	 */
	time = ksmbd_UnixTimeToNT(ksmbd_kstat->kstat->ctime);
	ksmbd_kstat->create_time = time;

	if (test_share_config_flag(work->tcon->share_conf,
				   KSMBD_SHARE_FLAG_STORE_DOS_ATTRS)) {
		xattr_len = ksmbd_vfs_getxattr(dentry,
					       XATTR_NAME_CREATION_TIME,
					       &create_time);
		if (xattr_len > 0)
			ksmbd_kstat->create_time = *((u64 *)create_time);
		ksmbd_free(create_time);
	}
}

/**
 * ksmbd_vfs_fsync() - vfs helper for smb fsync
 * @work:	work
 * @fid:	file id of open file
 *
 * Return:	0 on success, otherwise error
 */
int ksmbd_vfs_fsync(struct ksmbd_work *work, uint64_t fid, uint64_t p_id)
{
	struct ksmbd_file *fp;
	int err;

	fp = ksmbd_lookup_fd_slow(work, fid, p_id);
	if (!fp) {
		ksmbd_err("failed to get filp for fid %llu\n", fid);
		return -ENOENT;
	}
	err = vfs_fsync(fp->filp, 0);
	if (err < 0)
		ksmbd_err("smb fsync failed, err = %d\n", err);
	ksmbd_fd_put(work, fp);
	return err;
}

/**
 * ksmbd_vfs_remove_file() - vfs helper for smb rmdir or unlink
 * @name:	absolute directory or file name
 *
 * Return:	0 on success, otherwise error
 */
int ksmbd_vfs_remove_file(struct ksmbd_work *work, char *name)
{
	struct path parent;
	struct dentry *dir, *dentry;
	char *last;
	int err = -ENOENT;

	last = extract_last_component(name);
	if (!last)
		return -ENOENT;

	if (ksmbd_override_fsids(work))
		return -ENOMEM;

	err = kern_path(name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &parent);
	if (err) {
		ksmbd_debug(VFS, "can't get %s, err %d\n", name, err);
		ksmbd_revert_fsids(work);
		roolback_path_modification(last);
		return err;
	}

	dir = parent.dentry;
	if (!d_inode(dir))
		goto out;

	inode_lock_nested(d_inode(dir), I_MUTEX_PARENT);
	dentry = lookup_one_len(last, dir, strlen(last));
	if (IS_ERR(dentry)) {
		err = PTR_ERR(dentry);
		ksmbd_debug(VFS, "%s: lookup failed, err %d\n", last, err);
		goto out_err;
	}

	if (!d_inode(dentry) || !d_inode(dentry)->i_nlink) {
		dput(dentry);
		err = -ENOENT;
		goto out_err;
	}

	if (S_ISDIR(d_inode(dentry)->i_mode)) {
		err = vfs_rmdir(d_inode(dir), dentry);
		if (err && err != -ENOTEMPTY)
			ksmbd_debug(VFS, "%s: rmdir failed, err %d\n", name,
				err);
	} else {
		err = vfs_unlink(d_inode(dir), dentry, NULL);
		if (err)
			ksmbd_debug(VFS, "%s: unlink failed, err %d\n", name,
				err);
	}

	dput(dentry);
out_err:
	inode_unlock(d_inode(dir));
out:
	roolback_path_modification(last);
	path_put(&parent);
	ksmbd_revert_fsids(work);
	return err;
}

/**
 * ksmbd_vfs_link() - vfs helper for creating smb hardlink
 * @oldname:	source file name
 * @newname:	hardlink name
 *
 * Return:	0 on success, otherwise error
 */
int ksmbd_vfs_link(struct ksmbd_work *work,
		const char *oldname, const char *newname)
{
	struct path oldpath, newpath;
	struct dentry *dentry;
	int err;

	if (ksmbd_override_fsids(work))
		return -ENOMEM;

	err = kern_path(oldname, LOOKUP_FOLLOW, &oldpath);
	if (err) {
		ksmbd_err("cannot get linux path for %s, err = %d\n",
				oldname, err);
		goto out1;
	}

	dentry = kern_path_create(AT_FDCWD, newname, &newpath,
			LOOKUP_FOLLOW | LOOKUP_REVAL);
	if (IS_ERR(dentry)) {
		err = PTR_ERR(dentry);
		ksmbd_err("path create err for %s, err %d\n", newname, err);
		goto out2;
	}

	err = -EXDEV;
	if (oldpath.mnt != newpath.mnt) {
		ksmbd_err("vfs_link failed err %d\n", err);
		goto out3;
	}

	err = vfs_link(oldpath.dentry, d_inode(newpath.dentry), dentry, NULL);
	if (err)
		ksmbd_debug(VFS, "vfs_link failed err %d\n", err);

out3:
	done_path_create(&newpath, dentry);
out2:
	path_put(&oldpath);
out1:
	ksmbd_revert_fsids(work);
	return err;
}

static int __ksmbd_vfs_rename(struct ksmbd_work *work,
			      struct dentry *src_dent_parent,
			      struct dentry *src_dent,
			      struct dentry *dst_dent_parent,
			      struct dentry *trap_dent,
			      char *dst_name)
{
	struct dentry *dst_dent;
	int err;

	spin_lock(&src_dent->d_lock);
	list_for_each_entry(dst_dent, &src_dent->d_subdirs, d_child) {
		struct ksmbd_file *child_fp;

		if (d_really_is_negative(dst_dent))
			continue;

		child_fp = ksmbd_lookup_fd_inode(d_inode(dst_dent));
		if (child_fp) {
			spin_unlock(&src_dent->d_lock);
			ksmbd_debug(VFS, "Forbid rename, sub file/dir is in use\n");
			return -EACCES;
		}
	}
	spin_unlock(&src_dent->d_lock);

	if (d_really_is_negative(src_dent_parent))
		return -ENOENT;
	if (d_really_is_negative(dst_dent_parent))
		return -ENOENT;
	if (d_really_is_negative(src_dent))
		return -ENOENT;
	if (src_dent == trap_dent)
		return -EINVAL;

	if (ksmbd_override_fsids(work))
		return -ENOMEM;

	dst_dent = lookup_one_len(dst_name, dst_dent_parent, strlen(dst_name));
	err = PTR_ERR(dst_dent);
	if (IS_ERR(dst_dent)) {
		ksmbd_err("lookup failed %s [%d]\n", dst_name, err);
		return err;
	}

	err = -ENOTEMPTY;
	if (dst_dent != trap_dent && !d_really_is_positive(dst_dent)) {
		err = vfs_rename(d_inode(src_dent_parent),
				 src_dent,
				 d_inode(dst_dent_parent),
				 dst_dent,
				 NULL,
				 0);
	}
	if (err)
		ksmbd_err("vfs_rename failed err %d\n", err);
	if (dst_dent)
		dput(dst_dent);
	ksmbd_revert_fsids(work);
	return err;
}

int ksmbd_vfs_fp_rename(struct ksmbd_work *work, struct ksmbd_file *fp,
		char *newname)
{
	struct path dst_path;
	struct dentry *src_dent_parent, *dst_dent_parent;
	struct dentry *src_dent, *trap_dent;
	char *dst_name;
	int err;

	dst_name = extract_last_component(newname);
	if (!dst_name)
		return -EINVAL;

	src_dent_parent = dget_parent(fp->filp->f_path.dentry);
	if (!src_dent_parent)
		return -EINVAL;

	src_dent = fp->filp->f_path.dentry;
	dget(src_dent);

	err = kern_path(newname, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &dst_path);
	if (err) {
		ksmbd_debug(VFS, "Cannot get path for %s [%d]\n", newname, err);
		goto out;
	}
	dst_dent_parent = dst_path.dentry;
	dget(dst_dent_parent);

	trap_dent = lock_rename(src_dent_parent, dst_dent_parent);
	err = __ksmbd_vfs_rename(work,
				 src_dent_parent,
				 src_dent,
				 dst_dent_parent,
				 trap_dent,
				 dst_name);
	unlock_rename(src_dent_parent, dst_dent_parent);
	dput(dst_dent_parent);
	path_put(&dst_path);
out:
	dput(src_dent);
	dput(src_dent_parent);
	return err;
}

/**
 * ksmbd_vfs_truncate() - vfs helper for smb file truncate
 * @work:	work
 * @name:	old filename
 * @fid:	file id of old file
 * @size:	truncate to given size
 *
 * Return:	0 on success, otherwise error
 */
int ksmbd_vfs_truncate(struct ksmbd_work *work, const char *name,
	struct ksmbd_file *fp, loff_t size)
{
	struct path path;
	int err = 0;
	struct inode *inode;

	if (name) {
		err = kern_path(name, 0, &path);
		if (err) {
			ksmbd_err("cannot get linux path for %s, err %d\n",
					name, err);
			return err;
		}
		err = vfs_truncate(&path, size);
		if (err)
			ksmbd_err("truncate failed for %s err %d\n",
					name, err);
		path_put(&path);
	} else {
		struct file *filp;

		filp = fp->filp;

		/* Do we need to break any of a levelII oplock? */
		smb_break_all_levII_oplock(work, fp, 1);

		inode = file_inode(filp);
		if (size < inode->i_size) {
			err = check_lock_range(filp, size,
					inode->i_size - 1, WRITE);
		} else {
			err = check_lock_range(filp, inode->i_size,
					size - 1, WRITE);
		}

		if (err) {
			ksmbd_err("failed due to lock\n");
			return -EAGAIN;
		}

		err = vfs_truncate(&filp->f_path, size);
		if (err)
			ksmbd_err("truncate failed for filename : %s err %d\n",
					fp->filename, err);
	}

	return err;
}

/**
 * ksmbd_vfs_listxattr() - vfs helper for smb list extended attributes
 * @dentry:	dentry of file for listing xattrs
 * @list:	destination buffer
 * @size:	destination buffer length
 *
 * Return:	xattr list length on success, otherwise error
 */
ssize_t ksmbd_vfs_listxattr(struct dentry *dentry, char **list)
{
	ssize_t size;
	char *vlist = NULL;

	size = vfs_listxattr(dentry, NULL, 0);
	if (size <= 0)
		return size;

	vlist = ksmbd_alloc(size);
	if (!vlist)
		return -ENOMEM;

	*list = vlist;
	size = vfs_listxattr(dentry, vlist, size);
	if (size < 0) {
		ksmbd_debug(VFS, "listxattr failed\n");
		ksmbd_vfs_xattr_free(vlist);
		*list = NULL;
	}

	return size;
}

static ssize_t ksmbd_vfs_xattr_len(struct dentry *dentry,
			   char *xattr_name)
{
	return vfs_getxattr(dentry, xattr_name, NULL, 0);
}

/**
 * ksmbd_vfs_getxattr() - vfs helper for smb get extended attributes value
 * @dentry:	dentry of file for getting xattrs
 * @xattr_name:	name of xattr name to query
 * @xattr_buf:	destination buffer xattr value
 *
 * Return:	read xattr value length on success, otherwise error
 */
ssize_t ksmbd_vfs_getxattr(struct dentry *dentry,
			   char *xattr_name,
			   char **xattr_buf)
{
	ssize_t xattr_len;
	char *buf;

	*xattr_buf = NULL;
	xattr_len = ksmbd_vfs_xattr_len(dentry, xattr_name);
	if (xattr_len < 0)
		return xattr_len;

	buf = kmalloc(xattr_len + 1, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	xattr_len = vfs_getxattr(dentry, xattr_name, (void *)buf, xattr_len);
	if (xattr_len > 0)
		*xattr_buf = buf;
	else
		kfree(buf);
	return xattr_len;
}

/**
 * ksmbd_vfs_setxattr() - vfs helper for smb set extended attributes value
 * @dentry:	dentry to set XATTR at
 * @name:	xattr name for setxattr
 * @value:	xattr value to set
 * @size:	size of xattr value
 * @flags:	destination buffer length
 *
 * Return:	0 on success, otherwise error
 */
int ksmbd_vfs_setxattr(struct dentry *dentry,
		       const char *attr_name,
		       const void *attr_value,
		       size_t attr_size,
		       int flags)
{
	int err;

	err = vfs_setxattr(dentry,
			   attr_name,
			   attr_value,
			   attr_size,
			   flags);
	if (err)
		ksmbd_debug(VFS, "setxattr failed, err %d\n", err);
	return err;
}

/**
 * ksmbd_vfs_set_fadvise() - convert smb IO caching options to linux options
 * @filp:	file pointer for IO
 * @options:	smb IO options
 */
void ksmbd_vfs_set_fadvise(struct file *filp, __le32 option)
{
	struct address_space *mapping;

	mapping = filp->f_mapping;

	if (!option || !mapping)
		return;

	if (option & FILE_WRITE_THROUGH_LE)
		filp->f_flags |= O_SYNC;
	else if (option & FILE_SEQUENTIAL_ONLY_LE) {
		filp->f_ra.ra_pages = inode_to_bdi(mapping->host)->ra_pages * 2;
		spin_lock(&filp->f_lock);
		filp->f_mode &= ~FMODE_RANDOM;
		spin_unlock(&filp->f_lock);
	} else if (option & FILE_RANDOM_ACCESS_LE) {
		spin_lock(&filp->f_lock);
		filp->f_mode |= FMODE_RANDOM;
		spin_unlock(&filp->f_lock);
	}
}

/**
 * ksmbd_vfs_lock() - vfs helper for smb file locking
 * @filp:	the file to apply the lock to
 * @cmd:	type of locking operation (F_SETLK, F_GETLK, etc.)
 * @flock:	The lock to be applied
 *
 * Return:	0 on success, otherwise error
 */
int ksmbd_vfs_lock(struct file *filp, int cmd,
			struct file_lock *flock)
{
	ksmbd_debug(VFS, "calling vfs_lock_file\n");
	return vfs_lock_file(filp, cmd, flock, NULL);
}

int ksmbd_vfs_readdir(struct file *file, struct ksmbd_readdir_data *rdata)
{
	return iterate_dir(file, &rdata->ctx);
}

int ksmbd_vfs_alloc_size(struct ksmbd_work *work,
			 struct ksmbd_file *fp,
			 loff_t len)
{
	smb_break_all_levII_oplock(work, fp, 1);
	return vfs_fallocate(fp->filp, FALLOC_FL_KEEP_SIZE, 0, len);
}

int ksmbd_vfs_zero_data(struct ksmbd_work *work,
			 struct ksmbd_file *fp,
			 loff_t off,
			 loff_t len)
{
	smb_break_all_levII_oplock(work, fp, 1);
	if (fp->f_ci->m_fattr & ATTR_SPARSE_FILE_LE)
		return vfs_fallocate(fp->filp,
			FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, off, len);

	return vfs_fallocate(fp->filp, FALLOC_FL_ZERO_RANGE, off, len);
}

int ksmbd_vfs_fiemap(struct ksmbd_file *fp, u64 start, u64 length,
	struct file_allocated_range_buffer *ranges,
	int in_count, int *out_count)
{
	struct inode *inode = FP_INODE(fp);
	struct super_block *sb = inode->i_sb;
	struct fiemap_extent_info fieinfo = { 0, };
	u64 maxbytes = (u64) sb->s_maxbytes, extent_len, end;
	int ret = 0;
	struct file_allocated_range_buffer *range;
	struct fiemap_extent *extents;
	int i, range_idx;

	if (!inode->i_op->fiemap)
		return -EOPNOTSUPP;

	if (start > maxbytes)
		return -EFBIG;

	/*
	 * Shrink request scope to what the fs can actually handle.
	 */
	if (length > maxbytes || (maxbytes - length) < start)
		length = maxbytes - start;

	fieinfo.fi_extents_max = 32;
	extents = kmalloc_array(fieinfo.fi_extents_max,
			sizeof(struct fiemap_extent), GFP_KERNEL);
	if (!extents)
		return -ENOMEM;
	fieinfo.fi_extents_start = (struct fiemap_extent __user *)extents;

	range_idx = 0;
	range = ranges + range_idx;
	range->file_offset = cpu_to_le64(start);
	range->length = 0;

	end = start + length;
	*out_count = 0;

	while (start < end) {
		ret = inode->i_op->fiemap(inode, &fieinfo, start, length);
		if (ret)
			goto out;
		else if (fieinfo.fi_extents_mapped == 0) {
			if (le64_to_cpu(range->length))
				*out_count = range_idx + 1;
			else
				*out_count = range_idx;
			goto out;
		}

		for (i = 0; i < fieinfo.fi_extents_mapped; i++) {
			if (extents[i].fe_logical <=
					le64_to_cpu(range->file_offset) +
					le64_to_cpu(range->length)) {
				length = end - le64_to_cpu(range->file_offset);
				extent_len = extents[i].fe_length;
				if (extents[i].fe_logical <
					le64_to_cpu(range->file_offset)) {
					u64 first_half =
						le64_to_cpu(range->file_offset)
						- extents[i].fe_logical;
					if (first_half > extent_len)
						continue;
					extent_len -= first_half;
				}
				extent_len = min_t(u64, extent_len,
						length);
				le64_add_cpu(&range->length,
						extent_len);
			} else {
				if (extents[i].fe_logical >= end)
					break;
				/* skip this increment if the range is
				 * not initialized
				 */
				if (range->length)
					range_idx++;
				if (range_idx >= in_count) {
					*out_count = range_idx;
					ret = -E2BIG;
					goto out;
				}

				length = end - extents[i].fe_logical;
				extent_len = min_t(u64, extents[i].fe_length,
						length);

				range = ranges + range_idx;
				range->file_offset =
					cpu_to_le64(extents[i].fe_logical);
				range->length = cpu_to_le64(extent_len);
			}

			if ((extents[i].fe_flags & FIEMAP_EXTENT_LAST) ||
					le64_to_cpu(range->file_offset) +
					le64_to_cpu(range->length) >= end) {
				*out_count = range_idx + 1;
				goto out;
			}
		}

		start = le64_to_cpu(range->file_offset) +
			le64_to_cpu(range->length);
		length = end - start;
	}

out:
	kfree(extents);
	return ret;
}

int ksmbd_vfs_remove_xattr(struct dentry *dentry, char *attr_name)
{
	return vfs_removexattr(dentry, attr_name);
}

void ksmbd_vfs_xattr_free(char *xattr)
{
	ksmbd_free(xattr);
}

int ksmbd_vfs_unlink(struct dentry *dir, struct dentry *dentry)
{
	int err = 0;

	dget(dentry);
	inode_lock_nested(d_inode(dir), I_MUTEX_PARENT);
	if (!d_inode(dentry) || !d_inode(dentry)->i_nlink) {
		err = -ENOENT;
		goto out;
	}

	if (S_ISDIR(d_inode(dentry)->i_mode))
		err = vfs_rmdir(d_inode(dir), dentry);
	else
		err = vfs_unlink(d_inode(dir), dentry, NULL);

out:
	inode_unlock(d_inode(dir));
	dput(dentry);
	if (err)
		ksmbd_debug(VFS, "failed to delete, err %d\n", err);

	return err;
}

/*
 * ksmbd_vfs_get_logical_sector_size() - get logical sector size from inode
 * @inode: inode
 *
 * Return: logical sector size
 */
unsigned short ksmbd_vfs_logical_sector_size(struct inode *inode)
{
	struct request_queue *q;
	unsigned short ret_val = 512;

	if (!inode->i_sb->s_bdev)
		return ret_val;

	q = inode->i_sb->s_bdev->bd_disk->queue;

	if (q && q->limits.logical_block_size)
		ret_val = q->limits.logical_block_size;

	return ret_val;
}

/*
 * ksmbd_vfs_get_smb2_sector_size() - get fs sector sizes
 * @inode: inode
 * @fs_ss: fs sector size struct
 */
void ksmbd_vfs_smb2_sector_size(struct inode *inode,
	struct ksmbd_fs_sector_size *fs_ss)
{
	struct request_queue *q;

	fs_ss->logical_sector_size = 512;
	fs_ss->physical_sector_size = 512;
	fs_ss->optimal_io_size = 512;

	if (!inode->i_sb->s_bdev)
		return;

	q = inode->i_sb->s_bdev->bd_disk->queue;

	if (q) {
		if (q->limits.logical_block_size)
			fs_ss->logical_sector_size =
				q->limits.logical_block_size;
		if (q->limits.physical_block_size)
			fs_ss->physical_sector_size =
				q->limits.physical_block_size;
		if (q->limits.io_opt)
			fs_ss->optimal_io_size = q->limits.io_opt;
	}
}

static int __dir_empty(struct dir_context *ctx,
				   const char *name,
				   int namlen,
				   loff_t offset,
				   u64 ino,
				   unsigned int d_type)
{
	struct ksmbd_readdir_data *buf;

	buf = container_of(ctx, struct ksmbd_readdir_data, ctx);
	buf->dirent_count++;

	if (buf->dirent_count > 2)
		return -ENOTEMPTY;
	return 0;
}

/**
 * ksmbd_vfs_empty_dir() - check for empty directory
 * @fp:	ksmbd file pointer
 *
 * Return:	true if directory empty, otherwise false
 */
int ksmbd_vfs_empty_dir(struct ksmbd_file *fp)
{
	int err;
	struct ksmbd_readdir_data readdir_data;

	memset(&readdir_data, 0, sizeof(struct ksmbd_readdir_data));

	set_ctx_actor(&readdir_data.ctx, __dir_empty);
	readdir_data.dirent_count = 0;

	err = ksmbd_vfs_readdir(fp->filp, &readdir_data);
	if (readdir_data.dirent_count > 2)
		err = -ENOTEMPTY;
	else
		err = 0;
	return err;
}

static int __caseless_lookup(struct dir_context *ctx,
			     const char *name,
			     int namlen,
			     loff_t offset,
			     u64 ino,
			     unsigned int d_type)
{
	struct ksmbd_readdir_data *buf;

	buf = container_of(ctx, struct ksmbd_readdir_data, ctx);

	if (buf->used != namlen)
		return 0;
	if (!strncasecmp((char *)buf->private, name, namlen)) {
		memcpy((char *)buf->private, name, namlen);
		buf->dirent_count = 1;
		return -EEXIST;
	}
	return 0;
}

/**
 * ksmbd_vfs_lookup_in_dir() - lookup a file in a directory
 * @dirname:	directory name
 * @filename:	filename to lookup
 *
 * Return:	0 on success, otherwise error
 */
static int ksmbd_vfs_lookup_in_dir(char *dirname, char *filename)
{
	struct path dir_path;
	int ret;
	struct file *dfilp;
	int flags = O_RDONLY|O_LARGEFILE;
	int dirnamelen = strlen(dirname);
	struct ksmbd_readdir_data readdir_data = {
		.ctx.actor	= __caseless_lookup,
		.private	= filename,
		.used		= strlen(filename),
	};

	ret = ksmbd_vfs_kern_path(dirname, 0, &dir_path, true);
	if (ret)
		goto error;

	dfilp = dentry_open(&dir_path, flags, current_cred());
	if (IS_ERR(dfilp)) {
		path_put(&dir_path);
		ksmbd_err("cannot open directory %s\n", dirname);
		ret = -EINVAL;
		goto error;
	}

	ret = ksmbd_vfs_readdir(dfilp, &readdir_data);
	if (readdir_data.dirent_count > 0)
		ret = 0;

	fput(dfilp);
	path_put(&dir_path);
error:
	dirname[dirnamelen] = '/';
	return ret;
}

/**
 * ksmbd_vfs_kern_path() - lookup a file and get path info
 * @name:	name of file for lookup
 * @flags:	lookup flags
 * @path:	if lookup succeed, return path info
 * @caseless:	caseless filename lookup
 *
 * Return:	0 on success, otherwise error
 */
int ksmbd_vfs_kern_path(char *name, unsigned int flags, struct path *path,
		bool caseless)
{
	char *filename = NULL;
	int err;

	err = kern_path(name, flags, path);
	if (!err)
		return err;

	if (caseless) {
		filename = extract_last_component(name);
		if (!filename)
			goto out;

		/* root reached */
		if (strlen(name) == 0)
			goto out;

		err = ksmbd_vfs_lookup_in_dir(name, filename);
		if (err)
			goto out;
		err = kern_path(name, flags, path);
	}

out:
	roolback_path_modification(filename);
	return err;
}

/**
 * ksmbd_vfs_init_kstat() - convert unix stat information to smb stat format
 * @p:          destination buffer
 * @ksmbd_kstat:      ksmbd kstat wrapper
 */
void *ksmbd_vfs_init_kstat(char **p, struct ksmbd_kstat *ksmbd_kstat)
{
	struct file_directory_info *info = (struct file_directory_info *)(*p);
	struct kstat *kstat = ksmbd_kstat->kstat;
	u64 time;

	info->FileIndex = 0;
	info->CreationTime = cpu_to_le64(ksmbd_kstat->create_time);
	time = ksmbd_UnixTimeToNT(kstat->atime);
	info->LastAccessTime = cpu_to_le64(time);
	time = ksmbd_UnixTimeToNT(kstat->mtime);
	info->LastWriteTime = cpu_to_le64(time);
	time = ksmbd_UnixTimeToNT(kstat->ctime);
	info->ChangeTime = cpu_to_le64(time);

	if (ksmbd_kstat->file_attributes & ATTR_DIRECTORY_LE) {
		info->EndOfFile = 0;
		info->AllocationSize = 0;
	} else {
		info->EndOfFile = cpu_to_le64(kstat->size);
		info->AllocationSize = cpu_to_le64(kstat->blocks << 9);
	}
	info->ExtFileAttributes = ksmbd_kstat->file_attributes;

	return info;
}

int ksmbd_vfs_fill_dentry_attrs(struct ksmbd_work *work,
				struct dentry *dentry,
				struct ksmbd_kstat *ksmbd_kstat)
{
	generic_fillattr(d_inode(dentry), ksmbd_kstat->kstat);
	__file_dentry_ctime(work, dentry, ksmbd_kstat);
	__fill_dentry_attributes(work, dentry, ksmbd_kstat);
	return 0;
}

ssize_t ksmbd_vfs_casexattr_len(struct dentry *dentry,
				char *attr_name,
				int attr_name_len)
{
	char *name, *xattr_list = NULL;
	ssize_t value_len = -ENOENT, xattr_list_len;

	xattr_list_len = ksmbd_vfs_listxattr(dentry, &xattr_list);
	if (xattr_list_len <= 0)
		goto out;

	for (name = xattr_list; name - xattr_list < xattr_list_len;
			name += strlen(name) + 1) {
		ksmbd_debug(VFS, "%s, len %zd\n", name, strlen(name));
		if (strncasecmp(attr_name, name, attr_name_len))
			continue;

		value_len = ksmbd_vfs_xattr_len(dentry, name);
		break;
	}

out:
	ksmbd_vfs_xattr_free(xattr_list);
	return value_len;
}

int ksmbd_vfs_xattr_stream_name(char *stream_name,
				char **xattr_stream_name,
				size_t *xattr_stream_name_size)
{
	int stream_name_size;
	char *xattr_stream_name_buf;

	stream_name_size = strlen(stream_name);
	*xattr_stream_name_size = stream_name_size + XATTR_NAME_STREAM_LEN + 1;
	xattr_stream_name_buf = kmalloc(*xattr_stream_name_size, GFP_KERNEL);
	if (!xattr_stream_name_buf)
		return -ENOMEM;

	memcpy(xattr_stream_name_buf,
		XATTR_NAME_STREAM,
		XATTR_NAME_STREAM_LEN);

	if (stream_name_size)
		memcpy(&xattr_stream_name_buf[XATTR_NAME_STREAM_LEN],
			stream_name,
			stream_name_size);

	xattr_stream_name_buf[*xattr_stream_name_size - 1] = '\0';
	*xattr_stream_name = xattr_stream_name_buf;

	return 0;
}


static int ksmbd_vfs_copy_file_range(struct file *file_in, loff_t pos_in,
				struct file *file_out, loff_t pos_out,
				size_t len)
{
	struct inode *inode_in = file_inode(file_in);
	struct inode *inode_out = file_inode(file_out);
	int ret;

	ret = vfs_copy_file_range(file_in, pos_in, file_out, pos_out, len, 0);
	/* do splice for the copy between different file systems */
	if (ret != -EXDEV)
		return ret;

	if (S_ISDIR(inode_in->i_mode) || S_ISDIR(inode_out->i_mode))
		return -EISDIR;
	if (!S_ISREG(inode_in->i_mode) || !S_ISREG(inode_out->i_mode))
		return -EINVAL;

	if (!(file_in->f_mode & FMODE_READ) ||
	    !(file_out->f_mode & FMODE_WRITE))
		return -EBADF;

	if (len == 0)
		return 0;

	file_start_write(file_out);

	/*
	 * skip the verification of the range of data. it will be done
	 * in do_splice_direct
	 */
	ret = do_splice_direct(file_in, &pos_in, file_out, &pos_out,
			len > MAX_RW_COUNT ? MAX_RW_COUNT : len, 0);
	if (ret > 0) {
		fsnotify_access(file_in);
		add_rchar(current, ret);
		fsnotify_modify(file_out);
		add_wchar(current, ret);
	}

	inc_syscr(current);
	inc_syscw(current);

	file_end_write(file_out);
	return ret;
}

int ksmbd_vfs_copy_file_ranges(struct ksmbd_work *work,
				struct ksmbd_file *src_fp,
				struct ksmbd_file *dst_fp,
				struct srv_copychunk *chunks,
				unsigned int chunk_count,
				unsigned int *chunk_count_written,
				unsigned int *chunk_size_written,
				loff_t *total_size_written)
{
	unsigned int i;
	loff_t src_off, dst_off, src_file_size;
	size_t len;
	int ret;

	*chunk_count_written = 0;
	*chunk_size_written = 0;
	*total_size_written = 0;

	if (!(src_fp->daccess & (FILE_READ_DATA_LE | FILE_GENERIC_READ_LE |
			FILE_GENERIC_ALL_LE | FILE_MAXIMAL_ACCESS_LE |
			FILE_EXECUTE_LE))) {
		ksmbd_err("no right to read(%s)\n", FP_FILENAME(src_fp));
		return -EACCES;
	}
	if (!(dst_fp->daccess & (FILE_WRITE_DATA_LE | FILE_APPEND_DATA_LE |
			FILE_GENERIC_WRITE_LE | FILE_GENERIC_ALL_LE |
			FILE_MAXIMAL_ACCESS_LE))) {
		ksmbd_err("no right to write(%s)\n", FP_FILENAME(dst_fp));
		return -EACCES;
	}

	if (ksmbd_stream_fd(src_fp) || ksmbd_stream_fd(dst_fp))
		return -EBADF;

	smb_break_all_levII_oplock(work, dst_fp, 1);

	for (i = 0; i < chunk_count; i++) {
		src_off = le64_to_cpu(chunks[i].SourceOffset);
		dst_off = le64_to_cpu(chunks[i].TargetOffset);
		len = le32_to_cpu(chunks[i].Length);

		if (check_lock_range(src_fp->filp, src_off,
				src_off + len - 1, READ))
			return -EAGAIN;
		if (check_lock_range(dst_fp->filp, dst_off,
				dst_off + len - 1, WRITE))
			return -EAGAIN;
	}

	src_file_size = i_size_read(file_inode(src_fp->filp));

	for (i = 0; i < chunk_count; i++) {
		src_off = le64_to_cpu(chunks[i].SourceOffset);
		dst_off = le64_to_cpu(chunks[i].TargetOffset);
		len = le32_to_cpu(chunks[i].Length);

		if (src_off + len > src_file_size)
			return -E2BIG;

		ret = ksmbd_vfs_copy_file_range(src_fp->filp, src_off,
				dst_fp->filp, dst_off, len);
		if (ret < 0)
			return ret;

		*chunk_count_written += 1;
		*total_size_written += ret;
	}
	return 0;
}

int ksmbd_vfs_posix_lock_wait(struct file_lock *flock)
{
	return wait_event_interruptible(flock->fl_wait, !flock->fl_blocker);
}

int ksmbd_vfs_posix_lock_wait_timeout(struct file_lock *flock, long timeout)
{
	return wait_event_interruptible_timeout(flock->fl_wait,
						!flock->fl_blocker,
						timeout);
}

void ksmbd_vfs_posix_lock_unblock(struct file_lock *flock)
{
	locks_delete_block(flock);
}
