/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Functions to handle the cached directory entries
 *
 *  Copyright (c) 2022, Ronnie Sahlberg <lsahlber@redhat.com>
 */

#ifndef _CACHED_DIR_H
#define _CACHED_DIR_H

#include <linux/seqlock.h>

struct cached_dirent {
	struct list_head entry;
	char *name;
	int namelen;
	loff_t pos;

	/* filled from cifs_fattr */
	u64 unique_id;
	unsigned int dtype;
};

struct cached_dirents {
	bool is_valid:1;
	bool is_failed:1;
	struct file *file; /*
			    * Used to associate the cache with a single
			    * open file instance.
			    */
	struct mutex de_mutex;
	loff_t pos;		 /* Expected ctx->pos */
	struct list_head entries;
	/* accounting for cached entries in this directory */
	unsigned long entries_count;
	unsigned long bytes_used;
};

struct cached_fid {
	struct list_head entry;
	struct rcu_head rcu;
	/*
	 * ->seqlock must be used:
	 * - write-locked when updating
	 * - rcu_read_lock() + seqcounted on reads
	 */
	seqlock_t seqlock;
	struct cached_fids *cfids;
	const char *path;
	unsigned long ctime; /* (jiffies) creation time, when cfid was created (cached) */
	unsigned long atime; /* (jiffies) access time, when it was last used */
	struct kref refcount;
	struct cifs_fid fid;
	struct cifs_tcon *tcon;
	struct dentry *dentry;
	struct smb2_file_all_info *file_all_info;
	struct cached_dirents dirents;
};

/* default MAX_CACHED_FIDS is 16 */
struct cached_fids {
	/*
	 * ->entries_seqlock must be used when accessing ->entries or ->num_entries:
	 * - write-locked when updating
	 * - rcu_read_lock() + seqcounted on reads
	 */
	seqlock_t entries_seqlock;
	int num_entries;
	struct list_head entries;
	struct delayed_work laundromat_work;
	/* aggregate accounting for all cached dirents under this tcon */
	atomic_long_t total_dirents_entries;
	atomic64_t total_dirents_bytes;

	/* convenience for parent lookups */
	int dirsep;
};

/* Lookup modes for find_cached_dir() */
enum {
	CFID_LOOKUP_PATH,
	CFID_LOOKUP_PARENT,
	CFID_LOOKUP_DENTRY,
	CFID_LOOKUP_LEASEKEY,
};

static inline bool cfid_expired(const struct cached_fid *cfid)
{
	return (cfid->atime && time_is_before_jiffies(cfid->atime + HZ * dir_cache_timeout));
}

static inline bool is_valid_cached_dir(struct cached_fid *cfid)
{
	return (cfid->fid.persistent_fid && cfid->ctime && !cfid_expired(cfid));
}

/* Module-wide directory cache accounting (defined in cifsfs.c) */
extern atomic64_t cifs_dircache_bytes_used; /* bytes across all mounts */
extern struct cached_fids *init_cached_dirs(void);
extern struct cached_fid *find_cached_dir(struct cached_fids *cfids, const void *key, int mode);
extern int open_cached_dir(unsigned int xid, struct cifs_tcon *tcon, const char *path,
			   struct cifs_sb_info *cifs_sb, struct cached_fid **cfid);
extern void close_cached_dir(struct cached_fid *cfid);
extern bool drop_cached_dir(struct cached_fids *cfids, const void *key, int mode);
extern void invalidate_cached_dirents(struct cached_fids *cfids, const void *key, int mode);
extern void close_all_cached_dirs(struct cifs_sb_info *cifs_sb);
extern void invalidate_all_cached_dirs(struct cached_fids *cfids);
#endif			/* _CACHED_DIR_H */
