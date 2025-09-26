// SPDX-License-Identifier: GPL-2.0
/*
 *  Functions to handle the cached directory entries
 *
 *  Copyright (c) 2022, Ronnie Sahlberg <lsahlber@redhat.com>
 */

#include <linux/namei.h>
#include "cifsglob.h"
#include "cifsproto.h"
#include "cifs_debug.h"
#include "smb2proto.h"
#include "cached_dir.h"

static struct cached_fid *init_cached_dir(const char *path);
static void smb2_close_cached_fid(struct kref *ref);

static inline void invalidate_cfid(struct cached_fid *cfid)
{
	/* callers must hold the list lock and do any list operations (del/move) themselves */
	lockdep_assert_held(&cfid->cfids->cfid_list_lock);

	if (is_valid_cached_dir(cfid))
		cfid->cfids->num_entries--;

	/* do not change other fields here! */
	cfid->time = 0;
	cfid->last_access_time = 1;
}

static inline void drop_cfid(struct cached_fid *cfid)
{
	struct dentry *dentry = NULL;

	spin_lock(&cfid->cfids->cfid_list_lock);
	invalidate_cfid(cfid);

	swap(cfid->dentry, dentry);
	spin_unlock(&cfid->cfids->cfid_list_lock);

	dput(dentry);

	if (cfid->is_open) {
		int rc;

		cfid->is_open = false;
		rc = SMB2_close(0, cfid->tcon, cfid->fid.persistent_fid, cfid->fid.volatile_fid);

		/* SMB2_close should handle -EBUSY or -EAGAIN */
		if (rc)
			cifs_dbg(VFS, "close cached dir rc %d\n", rc);
	}
}

/*
 * Find a cached dir based on @key and @mode (raw lookup).
 * The only validation done here is if cfid is not going down (last_access_time != 1).
 *
 * If @wait_open is true, keep retrying until cfid transitions from 'opening' to valid/invalid.
 *
 * Callers must handle any other validation as needed.
 * Returned cfid, if found, has a ref taken, regardless of state.
 */
static struct cached_fid *find_cfid(struct cached_fids *cfids, const void *key, int mode,
				    bool wait_open)
{
	struct cached_fid *cfid, *found;
	bool match;

	if (!cfids || !key)
		return NULL;

retry_find:
	found = NULL;

	spin_lock(&cfids->cfid_list_lock);
	list_for_each_entry(cfid, &cfids->entries, entry) {
		/* don't even bother checking if it's going away */
		if (cfid->last_access_time == 1)
			continue;

		if (mode == CFID_LOOKUP_PATH)
			match = !strcmp(cfid->path, (char *)key);

		if (mode == CFID_LOOKUP_DENTRY)
			match = (cfid->dentry == key);

		if (mode == CFID_LOOKUP_LEASEKEY)
			match = !memcmp(cfid->fid.lease_key, (u8 *)key, SMB2_LEASE_KEY_SIZE);

		if (!match)
			continue;

		/* only get a ref here if not waiting for open */
		if (!wait_open)
			kref_get(&cfid->refcount);
		found = cfid;
		break;
	}
	spin_unlock(&cfids->cfid_list_lock);

	if (wait_open && found) {
		/* cfid is being opened in open_cached_dir(), retry lookup */
		if (found->has_lease && !found->time && !found->last_access_time)
			goto retry_find;

		/* we didn't get a ref above, so get one now */
		kref_get(&found->refcount);
	}

	return found;
}

static struct dentry *
path_to_dentry(struct cifs_sb_info *cifs_sb, const char *path)
{
	struct dentry *dentry;
	const char *s, *p;
	char sep;

	sep = CIFS_DIR_SEP(cifs_sb);
	dentry = dget(cifs_sb->root);
	s = path;

	do {
		struct inode *dir = d_inode(dentry);
		struct dentry *child;

		if (!S_ISDIR(dir->i_mode)) {
			dput(dentry);
			dentry = ERR_PTR(-ENOTDIR);
			break;
		}

		/* skip separators */
		while (*s == sep)
			s++;
		if (!*s)
			break;
		p = s++;
		/* next separator */
		while (*s && *s != sep)
			s++;

		child = lookup_noperm_positive_unlocked(&QSTR_LEN(p, s - p),
							dentry);
		dput(dentry);
		dentry = child;
	} while (!IS_ERR(dentry));
	return dentry;
}

static const char *path_no_prefix(struct cifs_sb_info *cifs_sb,
				  const char *path)
{
	size_t len = 0;

	if (!*path)
		return path;

	if ((cifs_sb->mnt_cifs_flags & CIFS_MOUNT_USE_PREFIX_PATH) &&
	    cifs_sb->prepath) {
		len = strlen(cifs_sb->prepath) + 1;
		if (unlikely(len > strlen(path)))
			return ERR_PTR(-EINVAL);
	}
	return path + len;
}

/*
 * Find a cached dir based on @key and @mode (caller exposed).
 * This function will retry lookup if cfid found is in opening state.
 *
 * Returns valid cfid (with updated last_access_time) or NULL.
 */
struct cached_fid *find_cached_dir(struct cached_fids *cfids, const void *key, int mode)
{
	struct cached_fid *cfid;

	if (!cfids || !key)
		return NULL;

	cfid = find_cfid(cfids, key, mode, true);
	if (cfid) {
		if (is_valid_cached_dir(cfid)) {
			cfid->last_access_time = jiffies;
		} else {
			kref_put(&cfid->refcount, smb2_close_cached_fid);
			cfid = NULL;
		}
	}

	return cfid;
}

/*
 * Open the and cache a directory handle.
 * If error then *cfid is not initialized.
 */
int open_cached_dir(unsigned int xid, struct cifs_tcon *tcon, const char *path,
		    struct cifs_sb_info *cifs_sb, struct cached_fid **ret_cfid)
{
	struct cifs_ses *ses;
	struct TCP_Server_Info *server;
	struct cifs_open_parms oparms;
	struct smb2_create_rsp *o_rsp = NULL;
	struct smb2_query_info_rsp *qi_rsp = NULL;
	int resp_buftype[2];
	struct smb_rqst rqst[2];
	struct kvec rsp_iov[2];
	struct kvec open_iov[SMB2_CREATE_IOV_SIZE];
	struct kvec qi_iov[1];
	int rc, flags = 0;
	__le16 *utf16_path = NULL;
	u8 oplock = SMB2_OPLOCK_LEVEL_II;
	struct cifs_fid *pfid;
	struct dentry *dentry;
	struct cached_fid *cfid;
	struct cached_fids *cfids;
	const char *npath;
	int retries = 0, cur_sleep = 1;
	__le32 lease_flags = 0;

	if (cifs_sb->root == NULL)
		return -ENOENT;

	if (tcon == NULL)
		return -EOPNOTSUPP;

	ses = tcon->ses;
	cfids = tcon->cfids;

	if (!cfids)
		return -EOPNOTSUPP;
replay_again:
	/* reinitialize for possible replay */
	flags = 0;
	oplock = SMB2_OPLOCK_LEVEL_II;
	dentry = NULL;
	cfid = NULL;
	*ret_cfid = NULL;
	server = cifs_pick_channel(ses);

	if (!server->ops->new_lease_key)
		return -EIO;

	utf16_path = cifs_convert_path_to_utf16(path, cifs_sb);
	if (!utf16_path)
		return -ENOMEM;

	/* find_cached_dir() already checks if cfid is valid, so no need to check here */
	cfid = find_cached_dir(cfids, path, CFID_LOOKUP_PATH);
	if (cfid) {
		rc = 0;
		goto out;
	}

	spin_lock(&cfids->cfid_list_lock);
	if (cfids->num_entries >= tcon->max_cached_dirs) {
		spin_unlock(&cfids->cfid_list_lock);
		rc = -ENOENT;
		goto out;
	}

	cfid = init_cached_dir(path);
	if (!cfid) {
		spin_unlock(&cfids->cfid_list_lock);
		rc = -ENOMEM;
		goto out;
	}

	cfid->cfids = cfids;
	cfids->num_entries++;
	list_add(&cfid->entry, &cfids->entries);
	spin_unlock(&cfids->cfid_list_lock);

	pfid = &cfid->fid;

	/*
	 * Skip any prefix paths in @path as lookup_noperm_positive_unlocked() ends up
	 * calling ->lookup() which already adds those through
	 * build_path_from_dentry().  Also, do it earlier as we might reconnect
	 * below when trying to send compounded request and then potentially
	 * having a different prefix path (e.g. after DFS failover).
	 */
	npath = path_no_prefix(cifs_sb, path);
	if (IS_ERR(npath)) {
		rc = PTR_ERR(npath);
		goto out;
	}

	if (!npath[0]) {
		dentry = dget(cifs_sb->root);
	} else {
		dentry = path_to_dentry(cifs_sb, npath);
		if (IS_ERR(dentry)) {
			dentry = NULL;
			rc = -ENOENT;
			goto out;
		}
		if (dentry->d_parent && server->dialect >= SMB30_PROT_ID) {
			struct cached_fid *parent_cfid;

			spin_lock(&cfids->cfid_list_lock);
			list_for_each_entry(parent_cfid, &cfids->entries, entry) {
				if (parent_cfid->dentry == dentry->d_parent) {
					if (!is_valid_cached_dir(parent_cfid))
						break;

					cifs_dbg(FYI, "found a parent cached file handle\n");

					lease_flags |= SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET_LE;
					memcpy(pfid->parent_lease_key, parent_cfid->fid.lease_key,
					       SMB2_LEASE_KEY_SIZE);
					break;
				}
			}
			spin_unlock(&cfids->cfid_list_lock);
		}
	}
	cfid->dentry = dentry;
	cfid->tcon = tcon;
	dentry = NULL;

	/*
	 * We do not hold the lock for the open because in case
	 * SMB2_open needs to reconnect.
	 * This is safe because no other thread will be able to get a ref
	 * to the cfid until we have finished opening the file and (possibly)
	 * acquired a lease.
	 */
	if (smb3_encryption_required(tcon))
		flags |= CIFS_TRANSFORM_REQ;

	server->ops->new_lease_key(pfid);

	memset(rqst, 0, sizeof(rqst));
	resp_buftype[0] = resp_buftype[1] = CIFS_NO_BUFFER;
	memset(rsp_iov, 0, sizeof(rsp_iov));

	/* Open */
	memset(&open_iov, 0, sizeof(open_iov));
	rqst[0].rq_iov = open_iov;
	rqst[0].rq_nvec = SMB2_CREATE_IOV_SIZE;

	oparms = (struct cifs_open_parms) {
		.tcon = tcon,
		.path = path,
		.create_options = cifs_create_options(cifs_sb, CREATE_NOT_FILE),
		.desired_access =  FILE_READ_DATA | FILE_READ_ATTRIBUTES |
				   FILE_READ_EA,
		.disposition = FILE_OPEN,
		.fid = pfid,
		.lease_flags = lease_flags,
		.replay = !!(retries),
	};

	rc = SMB2_open_init(tcon, server,
			    &rqst[0], &oplock, &oparms, utf16_path);
	if (rc)
		goto oshr_free;
	smb2_set_next_command(tcon, &rqst[0]);

	memset(&qi_iov, 0, sizeof(qi_iov));
	rqst[1].rq_iov = qi_iov;
	rqst[1].rq_nvec = 1;

	rc = SMB2_query_info_init(tcon, server,
				  &rqst[1], COMPOUND_FID,
				  COMPOUND_FID, FILE_ALL_INFORMATION,
				  SMB2_O_INFO_FILE, 0,
				  sizeof(struct smb2_file_all_info) +
				  PATH_MAX * 2, 0, NULL);
	if (rc)
		goto oshr_free;

	smb2_set_related(&rqst[1]);

	if (retries) {
		smb2_set_replay(server, &rqst[0]);
		smb2_set_replay(server, &rqst[1]);
	}

	rc = compound_send_recv(xid, ses, server,
				flags, 2, rqst,
				resp_buftype, rsp_iov);
	if (rc) {
		if (rc == -EREMCHG) {
			tcon->need_reconnect = true;
			pr_warn_once("server share %s deleted\n",
				     tcon->tree_name);
		}
		goto oshr_free;
	}
	cfid->is_open = true;

	spin_lock(&cfids->cfid_list_lock);

	o_rsp = (struct smb2_create_rsp *)rsp_iov[0].iov_base;
	oparms.fid->persistent_fid = o_rsp->PersistentFileId;
	oparms.fid->volatile_fid = o_rsp->VolatileFileId;
#ifdef CONFIG_CIFS_DEBUG2
	oparms.fid->mid = le64_to_cpu(o_rsp->hdr.MessageId);
#endif /* CIFS_DEBUG2 */


	if (o_rsp->OplockLevel != SMB2_OPLOCK_LEVEL_LEASE) {
		spin_unlock(&cfids->cfid_list_lock);
		rc = -EINVAL;
		goto oshr_free;
	}

	rc = smb2_parse_contexts(server, rsp_iov,
				 &oparms.fid->epoch,
				 oparms.fid->lease_key,
				 &oplock, NULL, NULL);
	if (rc) {
		spin_unlock(&cfids->cfid_list_lock);
		goto oshr_free;
	}

	rc = -EINVAL;
	if (!(oplock & SMB2_LEASE_READ_CACHING_HE)) {
		spin_unlock(&cfids->cfid_list_lock);
		goto oshr_free;
	}
	qi_rsp = (struct smb2_query_info_rsp *)rsp_iov[1].iov_base;
	if (le32_to_cpu(qi_rsp->OutputBufferLength) < sizeof(struct smb2_file_all_info)) {
		spin_unlock(&cfids->cfid_list_lock);
		goto oshr_free;
	}
	if (!smb2_validate_and_copy_iov(
				le16_to_cpu(qi_rsp->OutputBufferOffset),
				sizeof(struct smb2_file_all_info),
				&rsp_iov[1], sizeof(struct smb2_file_all_info),
				(char *)&cfid->file_all_info))
		cfid->file_all_info_is_valid = true;

	cfid->time = jiffies;
	cfid->last_access_time = jiffies;
	spin_unlock(&cfids->cfid_list_lock);
	/* At this point the directory handle is fully cached */
	rc = 0;

oshr_free:
	SMB2_open_free(&rqst[0]);
	SMB2_query_info_free(&rqst[1]);
	free_rsp_buf(resp_buftype[0], rsp_iov[0].iov_base);
	free_rsp_buf(resp_buftype[1], rsp_iov[1].iov_base);
out:
	/* cfid invalidated in the mean time, drop it below */
	if (!rc && !is_valid_cached_dir(cfid))
		rc = -ENOENT;

	if (rc) {
		if (cfid) {
			drop_cfid(cfid);
			kref_put(&cfid->refcount, smb2_close_cached_fid);
		}
	} else {
		*ret_cfid = cfid;
		atomic_inc(&tcon->num_remote_opens);
	}
	kfree(utf16_path);

	if (is_replayable_error(rc) &&
	    smb2_should_replay(tcon, &retries, &cur_sleep))
		goto replay_again;

	return rc;
}

static void
smb2_close_cached_fid(struct kref *ref)
{
	struct cached_fid *cfid = container_of(ref, struct cached_fid, refcount);
	struct cached_dirent *de, *q;

	drop_cfid(cfid);

	/* Delete all cached dirent names */
	list_for_each_entry_safe(de, q, &cfid->dirents.entries, entry) {
		list_del(&de->entry);
		kfree(de->name);
		kfree(de);
	}

	kfree(cfid->path);
	cfid->path = NULL;
	kfree(cfid);
}

bool drop_cached_dir(struct cached_fids *cfids, const void *key, int mode)
{
	struct cached_fid *cfid;

	if (!cfids || !key)
		return false;

	/*
	 * Raw lookup here as we _must_ find any matching cfid, no matter its state.
	 * Also, we might be racing with the SMB2 open in open_cached_dir(), so no need to wait
	 * for it to finish.
	 */
	cfid = find_cfid(cfids, key, mode, false);
	if (!cfid)
		return false;

	if (mode != CFID_LOOKUP_LEASEKEY) {
		drop_cfid(cfid);
	} else {
		/* we're locked in smb2_is_valid_lease_break(), so can't dput/close here */
		spin_lock(&cfids->cfid_list_lock);
		invalidate_cfid(cfid);
		spin_unlock(&cfids->cfid_list_lock);
	}

	/* put lookup ref */
	kref_put(&cfid->refcount, smb2_close_cached_fid);
	mod_delayed_work(cfid_put_wq, &cfids->laundromat_work, 0);

	return true;
}

void close_cached_dir(struct cached_fid *cfid)
{
	kref_put(&cfid->refcount, smb2_close_cached_fid);
}

static void invalidate_all_cfids(struct cached_fids *cfids, bool closed)
{
	struct cached_fid *cfid, *q;

	if (!cfids)
		return;

	/* mark all the cfids as closed and invalidate them for laundromat cleanup */
	spin_lock(&cfids->cfid_list_lock);
	list_for_each_entry_safe(cfid, q, &cfids->entries, entry) {
		invalidate_cfid(cfid);
		cfid->has_lease = false;
		if (closed)
			cfid->is_open = false;
	}
	spin_unlock(&cfids->cfid_list_lock);

	/* run laundromat unconditionally now as there might have been previously queued work */
	mod_delayed_work(cfid_put_wq, &cfids->laundromat_work, 0);
}

/*
 * Called from cifs_kill_sb when we unmount a share
 */
void close_all_cached_dirs(struct cifs_sb_info *cifs_sb)
{
	struct rb_root *root = &cifs_sb->tlink_tree;
	struct rb_node *node;
	struct cifs_tcon *tcon;
	struct tcon_link *tlink;

	spin_lock(&cifs_sb->tlink_tree_lock);
	for (node = rb_first(root); node; node = rb_next(node)) {
		tlink = rb_entry(node, struct tcon_link, tl_rbnode);
		tcon = tlink_tcon(tlink);
		if (IS_ERR(tcon))
			continue;

		invalidate_all_cfids(tcon->cfids, false);
	}
	spin_unlock(&cifs_sb->tlink_tree_lock);

	/* Flush any pending work that will drop dentries */
	flush_workqueue(cfid_put_wq);
}

/*
 * Invalidate all cached dirs when a TCON has been reset
 * due to a session loss.
 */
void invalidate_all_cached_dirs(struct cached_fids *cfids)
{
	if (cfids == NULL)
		return;

	invalidate_all_cfids(cfids, true);
	flush_delayed_work(&cfids->laundromat_work);
}

static struct cached_fid *init_cached_dir(const char *path)
{
	struct cached_fid *cfid;

	cfid = kzalloc(sizeof(*cfid), GFP_ATOMIC);
	if (!cfid)
		return NULL;

	cfid->path = kstrdup(path, GFP_ATOMIC);
	if (!cfid->path) {
		kfree(cfid);
		return NULL;
	}

	INIT_LIST_HEAD(&cfid->entry);
	INIT_LIST_HEAD(&cfid->dirents.entries);
	mutex_init(&cfid->dirents.de_mutex);

	/* this is our ref */
	kref_init(&cfid->refcount);

	/* this is caller ref */
	kref_get(&cfid->refcount);

	/*
	 * Set @cfid->has_lease to true during construction so that the lease
	 * reference can be put in cached_dir_lease_break() due to a potential
	 * lease break right after the request is sent or while @cfid is still
	 * being cached, or if a reconnection is triggered during construction.
	 * Concurrent processes won't be to use it yet due to @cfid->time being
	 * zero.
	 */
	cfid->has_lease = true;

	return cfid;
}

static void cfids_laundromat_worker(struct work_struct *work)
{
	struct cached_fids *cfids;
	struct cached_fid *cfid, *q;
	LIST_HEAD(entry);

	cfids = container_of(work, struct cached_fids, laundromat_work.work);

	spin_lock(&cfids->cfid_list_lock);
	list_for_each_entry_safe(cfid, q, &cfids->entries, entry) {
		if (cfid_expired(cfid)) {
			invalidate_cfid(cfid);
			list_move(&cfid->entry, &entry);
		}
	}
	spin_unlock(&cfids->cfid_list_lock);

	list_for_each_entry_safe(cfid, q, &entry, entry) {
		list_del(&cfid->entry);

		/*
		 * If a cfid reached here, we must cleanup anything unrelated to it, i.e. dentry and
		 * remote fid.
		 *
		 * For the cfid itself, we only drop our own ref (kref_init).  If there are still
		 * concurrent ref-holders, they'll drop it later (cfid is already invalid at this
		 * point, so can't be found anymore).
		 *
		 * No risk for a double list_del() here because cfid is only on this list now.
		 */
		drop_cfid(cfid);
		kref_put(&cfid->refcount, smb2_close_cached_fid);
	}

	queue_delayed_work(cfid_put_wq, &cfids->laundromat_work, dir_cache_timeout * HZ);
}

struct cached_fids *init_cached_dirs(void)
{
	struct cached_fids *cfids;

	cfids = kzalloc(sizeof(*cfids), GFP_KERNEL);
	if (!cfids)
		return NULL;
	spin_lock_init(&cfids->cfid_list_lock);
	INIT_LIST_HEAD(&cfids->entries);

	INIT_DELAYED_WORK(&cfids->laundromat_work, cfids_laundromat_worker);
	queue_delayed_work(cfid_put_wq, &cfids->laundromat_work,
			   dir_cache_timeout * HZ);

	atomic_long_set(&cfids->total_dirents_entries, 0);
	atomic64_set(&cfids->total_dirents_bytes, 0);

	return cfids;
}
