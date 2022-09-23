// SPDX-License-Identifier: LGPL-2.1
/*
 *
 *   Copyright (C) International Business Machines  Corp., 2002, 2011
 *                 Etersoft, 2012
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *              Jeremy Allison (jra@samba.org) 2006
 *              Pavel Shilovsky (pshilovsky@samba.org) 2012
 *
 */

#include <linux/fs.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/net.h>
#include <linux/delay.h>
#include <linux/uaccess.h>
#include <asm/processor.h>
#include <linux/mempool.h>
#include <linux/highmem.h>
#include <crypto/aead.h>
#include "cifsglob.h"
#include "cifsproto.h"
#include "smb2proto.h"
#include "cifs_debug.h"
#include "smb2status.h"
#include "smb2glob.h"

int
smb2_init_secmechs(struct TCP_Server_Info *server)
{
	int rc = 0;

	if (server->dialect >= SMB30_PROT_ID &&
	    (server->capabilities & SMB2_GLOBAL_CAP_ENCRYPTION)) {
		if (server->cipher_type == SMB2_ENCRYPTION_AES128_GCM ||
		    server->cipher_type == SMB2_ENCRYPTION_AES256_GCM) {
			rc = smb3_crypto_aead_allocate("gcm(aes)", &server->secmech.enc);
			if (!rc)
				rc = smb3_crypto_aead_allocate("gcm(aes)", &server->secmech.dec);
		} else {
			rc = smb3_crypto_aead_allocate("ccm(aes)", &server->secmech.enc);
			if (!rc)
				rc = smb3_crypto_aead_allocate("ccm(aes)", &server->secmech.dec);
		}

		if (rc)
			return rc;
	}

	if (server->signing_algorithm == SIGNING_ALG_AES_GMAC) {
		cifs_free_hash(&server->secmech.sign.shash);
		cifs_free_hash(&server->secmech.verify.shash);

		rc = smb3_crypto_aead_allocate("gcm(aes)", &server->secmech.sign.aead);
		if (!rc)
			rc = smb3_crypto_aead_allocate("gcm(aes)", &server->secmech.verify.aead);
		if (rc) {
			smb3_crypto_aead_free(&server->secmech.sign.aead);
			return rc;
		}

		server->secmech.calc_signature = smb311_calc_signature;
	} else {
		char *shash_alg;

		if (server->dialect >= SMB30_PROT_ID)
			shash_alg = "cmac(aes)";
		else
			shash_alg = "hmac(sha256)";

		rc = cifs_alloc_hash(shash_alg, &server->secmech.sign.shash);
		if (!rc)
			rc = cifs_alloc_hash(shash_alg, &server->secmech.verify.shash);
		if (rc) {
			cifs_free_hash(&server->secmech.sign.shash);
			return rc;
		}

		server->secmech.calc_signature = smb2_calc_signature;
	}

	return rc;
}

static int
smb3_setup_keys(struct TCP_Server_Info *server, u8 *sign_key, u8 *enc_key, u8 *dec_key)
{
	unsigned int crypt_keylen = 0;
	int rc = 0;

	if (!(server->capabilities & SMB2_GLOBAL_CAP_ENCRYPTION) || !enc_key || !dec_key)
		goto setup_sign;

	if (server->cipher_type == SMB2_ENCRYPTION_AES256_CCM ||
	    server->cipher_type == SMB2_ENCRYPTION_AES256_GCM)
		crypt_keylen = SMB3_GCM256_CRYPTKEY_SIZE;
	else
		crypt_keylen = SMB3_GCM128_CRYPTKEY_SIZE;

	rc = crypto_aead_setkey(server->secmech.enc, enc_key, crypt_keylen);
	if (!rc)
		rc = crypto_aead_setkey(server->secmech.dec, dec_key, crypt_keylen);
	if (rc) {
		cifs_server_dbg(VFS, "%s: Failed to set encryption/decryption key, rc=%d\n",
				__func__, rc);
		return rc;
	}

	rc = crypto_aead_setauthsize(server->secmech.enc, SMB2_SIGNATURE_SIZE);
	if (!rc)
		rc = crypto_aead_setauthsize(server->secmech.dec, SMB2_SIGNATURE_SIZE);
	if (rc) {
		cifs_server_dbg(VFS, "%s: Failed to set encryption/decryption authsize, rc=%d\n",
				__func__, rc);
		return rc;
	}
setup_sign:
	if (server->signing_algorithm == SIGNING_ALG_AES_GMAC) {
		rc = crypto_aead_setkey(server->secmech.sign.aead, sign_key, SMB3_SIGN_KEY_SIZE);
		if (!rc)
			rc = crypto_aead_setkey(server->secmech.verify.aead, sign_key,
						SMB3_SIGN_KEY_SIZE);
		if (rc) {
			cifs_server_dbg(VFS, "%s: Failed to set AES-GMAC key, rc=%d\n",
					__func__, rc);
			return rc;
		}

		rc = crypto_aead_setauthsize(server->secmech.sign.aead, SMB2_SIGNATURE_SIZE);
		if (!rc)
			rc = crypto_aead_setauthsize(server->secmech.verify.aead,
						     SMB2_SIGNATURE_SIZE);
		if (rc)
			cifs_server_dbg(VFS, "%s: Failed to set AES-GMAC authsize, rc=%d\n",
					__func__, rc);
	} else {
		rc = crypto_shash_setkey(server->secmech.sign.shash->tfm, sign_key,
					 SMB3_SIGN_KEY_SIZE);
		if (!rc)
			rc = crypto_shash_setkey(server->secmech.verify.shash->tfm, sign_key,
						 SMB3_SIGN_KEY_SIZE);
		if (rc)
			cifs_server_dbg(VFS, "%s: Failed to set %s signing key, rc=%d\n", __func__,
					crypto_shash_alg_name(server->secmech.sign.shash->tfm), rc);
	}

	return rc;
}

static struct cifs_ses *
smb2_find_smb_ses_unlocked(struct TCP_Server_Info *server, __u64 ses_id)
{
	struct cifs_ses *ses;

	list_for_each_entry(ses, &server->smb_ses_list, smb_ses_list) {
		if (ses->Suid != ses_id)
			continue;
		++ses->ses_count;
		return ses;
	}

	return NULL;
}

struct cifs_ses *
smb2_find_smb_ses(struct TCP_Server_Info *server, __u64 ses_id)
{
	struct cifs_ses *ses;

	spin_lock(&cifs_tcp_ses_lock);
	ses = smb2_find_smb_ses_unlocked(server, ses_id);
	spin_unlock(&cifs_tcp_ses_lock);

	return ses;
}

static struct cifs_tcon *
smb2_find_smb_sess_tcon_unlocked(struct cifs_ses *ses, __u32  tid)
{
	struct cifs_tcon *tcon;

	list_for_each_entry(tcon, &ses->tcon_list, tcon_list) {
		if (tcon->tid != tid)
			continue;
		++tcon->tc_count;
		return tcon;
	}

	return NULL;
}

/*
 * Obtain tcon corresponding to the tid in the given
 * cifs_ses
 */

struct cifs_tcon *
smb2_find_smb_tcon(struct TCP_Server_Info *server, __u64 ses_id, __u32  tid)
{
	struct cifs_ses *ses;
	struct cifs_tcon *tcon;

	spin_lock(&cifs_tcp_ses_lock);
	ses = smb2_find_smb_ses_unlocked(server, ses_id);
	if (!ses) {
		spin_unlock(&cifs_tcp_ses_lock);
		return NULL;
	}
	tcon = smb2_find_smb_sess_tcon_unlocked(ses, tid);
	if (!tcon) {
		cifs_put_smb_ses(ses);
		spin_unlock(&cifs_tcp_ses_lock);
		return NULL;
	}
	spin_unlock(&cifs_tcp_ses_lock);
	/* tcon already has a ref to ses, so we don't need ses anymore */
	cifs_put_smb_ses(ses);

	return tcon;
}

int
smb2_calc_signature(struct smb_rqst *rqst, struct TCP_Server_Info *server, bool verify)
{
	int rc;
	unsigned char sig[SMB2_HMACSHA256_SIZE]; /* big enough for HMAC-SHA256 and AES-CMAC */
	unsigned char *sigptr = sig;
	struct kvec *iov = rqst->rq_iov;
	struct smb2_hdr *shdr = (struct smb2_hdr *)iov[0].iov_base;
	struct shash_desc *shash = NULL;
	struct smb_rqst drqst;

	memset(sig, 0x0, SMB2_HMACSHA256_SIZE);
	memset(shdr->Signature, 0x0, SMB2_SIGNATURE_SIZE);

	if (verify)
		shash = server->secmech.verify.shash;
	else
		shash = server->secmech.sign.shash;

	rc = crypto_shash_init(shash);
	if (rc) {
		cifs_server_dbg(VFS, "%s: Could not init %s\n", __func__,
				crypto_shash_alg_name(shash->tfm));
		return rc;
	}

	/*
	 * For SMB2+, __cifs_calc_signature() expects to sign only the actual
	 * data, that is, iov[0] should not contain a rfc1002 length.
	 *
	 * Sign the rfc1002 length prior to passing the data (iov[1-N]) down to
	 * __cifs_calc_signature().
	 */
	drqst = *rqst;
	if (drqst.rq_nvec >= 2 && iov[0].iov_len == 4) {
		rc = crypto_shash_update(shash, iov[0].iov_base, iov[0].iov_len);
		if (rc) {
			cifs_server_dbg(VFS, "%s: Could not update with payload, rc=%d\n",
					__func__, rc);
			return rc;
		}
		drqst.rq_iov++;
		drqst.rq_nvec--;
	}

	rc = __cifs_calc_signature(&drqst, server, sigptr, shash);
	if (!rc)
		memcpy(shdr->Signature, sigptr, SMB2_SIGNATURE_SIZE);

	return rc;
}

static int generate_key(struct cifs_ses *ses, struct kvec label,
			struct kvec context, __u8 *key, unsigned int key_size)
{
	unsigned char zero = 0x0;
	__u8 i[4] = {0, 0, 0, 1};
	__u8 L128[4] = {0, 0, 0, 128};
	__u8 L256[4] = {0, 0, 1, 0};
	int rc = 0;
	unsigned char prfhash[SMB2_HMACSHA256_SIZE];
	unsigned char *hashptr = prfhash;
	struct TCP_Server_Info *server = ses->server;
	struct shash_desc *hmac_sha256 = NULL;

	memset(prfhash, 0x0, SMB2_HMACSHA256_SIZE);
	memset(key, 0x0, key_size);

	/* do not reuse the server's secmech TFM */
	rc = cifs_alloc_hash("hmac(sha256)", &hmac_sha256);
	if (rc) {
		cifs_server_dbg(VFS, "%s: crypto alloc failed\n", __func__);
		goto smb3signkey_ret;
	}

	rc = crypto_shash_setkey(hmac_sha256->tfm, ses->auth_key.response,
				 SMB2_NTLMV2_SESSKEY_SIZE);
	if (rc) {
		cifs_server_dbg(VFS, "%s: Could not set with session key\n", __func__);
		goto smb3signkey_ret;
	}

	rc = crypto_shash_init(hmac_sha256);
	if (rc) {
		cifs_server_dbg(VFS, "%s: Could not init sign hmac\n", __func__);
		goto smb3signkey_ret;
	}

	rc = crypto_shash_update(hmac_sha256, i, 4);
	if (rc) {
		cifs_server_dbg(VFS, "%s: Could not update with n\n", __func__);
		goto smb3signkey_ret;
	}

	rc = crypto_shash_update(hmac_sha256, label.iov_base, label.iov_len);
	if (rc) {
		cifs_server_dbg(VFS, "%s: Could not update with label\n", __func__);
		goto smb3signkey_ret;
	}

	rc = crypto_shash_update(hmac_sha256, &zero, 1);
	if (rc) {
		cifs_server_dbg(VFS, "%s: Could not update with zero\n", __func__);
		goto smb3signkey_ret;
	}

	rc = crypto_shash_update(hmac_sha256, context.iov_base, context.iov_len);
	if (rc) {
		cifs_server_dbg(VFS, "%s: Could not update with context\n", __func__);
		goto smb3signkey_ret;
	}

	if ((server->cipher_type == SMB2_ENCRYPTION_AES256_CCM) ||
		(server->cipher_type == SMB2_ENCRYPTION_AES256_GCM)) {
		rc = crypto_shash_update(hmac_sha256, L256, 4);
	} else {
		rc = crypto_shash_update(hmac_sha256, L128, 4);
	}
	if (rc) {
		cifs_server_dbg(VFS, "%s: Could not update with L\n", __func__);
		goto smb3signkey_ret;
	}

	rc = crypto_shash_final(hmac_sha256, hashptr);
	if (rc) {
		cifs_server_dbg(VFS, "%s: Could not generate sha256 hash\n", __func__);
		goto smb3signkey_ret;
	}

	memcpy(key, hashptr, key_size);

smb3signkey_ret:
	cifs_free_hash(&hmac_sha256);
	return rc;
}

struct derivation {
	struct kvec label;
	struct kvec context;
};

struct derivation_triplet {
	struct derivation signing;
	struct derivation encryption;
	struct derivation decryption;
};

static int
generate_smb3signingkey(struct cifs_ses *ses,
			struct TCP_Server_Info *server,
			const struct derivation_triplet *ptriplet)
{
	int rc;
	bool is_binding = false;
	int chan_index = 0;
	u8 sign_key[SMB3_SIGN_KEY_SIZE] = { 0 };
	u8 enc_key[SMB3_ENC_DEC_KEY_SIZE] = { 0 };
	u8 dec_key[SMB3_ENC_DEC_KEY_SIZE] = { 0 };

	spin_lock(&ses->chan_lock);
	is_binding = !CIFS_ALL_CHANS_NEED_RECONNECT(ses);
	chan_index = cifs_ses_get_chan_index(ses, server);
	/* TODO: introduce ref counting for channels when the can be freed */
	spin_unlock(&ses->chan_lock);

	/*
	 * All channels use the same encryption/decryption keys but
	 * they have their own signing key.
	 *
	 * When we generate the keys, check if it is for a new channel
	 * (binding) in which case we only need to generate a signing
	 * key and store it in the channel as to not overwrite the
	 * master connection signing key stored in the session
	 */

	if (is_binding) {
		rc = generate_key(ses, ptriplet->signing.label,
				  ptriplet->signing.context,
				  sign_key, SMB3_SIGN_KEY_SIZE);
		if (rc)
			goto out_zero_keys;

		rc = smb3_setup_keys(ses->chans[chan_index].server, sign_key, NULL, NULL);
		if (rc)
			goto out_zero_keys;
	} else {
		rc = generate_key(ses, ptriplet->signing.label,
				  ptriplet->signing.context,
				  sign_key, SMB3_SIGN_KEY_SIZE);
		if (rc)
			goto out_zero_keys;

		rc = generate_key(ses, ptriplet->encryption.label,
				  ptriplet->encryption.context,
				  enc_key, SMB3_ENC_DEC_KEY_SIZE);
		if (rc)
			goto out_zero_keys;

		rc = generate_key(ses, ptriplet->decryption.label,
				  ptriplet->decryption.context,
				  dec_key, SMB3_ENC_DEC_KEY_SIZE);
		if (rc)
			goto out_zero_keys;

		rc = smb3_setup_keys(ses->server, sign_key, enc_key, dec_key);
		if (rc)
			goto out_zero_keys;
	}
out_zero_keys:
#ifdef CONFIG_CIFS_DEBUG_DUMP_KEYS
	/* only leave keys in memory if debugging */
	memcpy(ses->smb3encryptionkey, enc_key, SMB3_ENC_DEC_KEY_SIZE);
	memcpy(ses->smb3decryptionkey, dec_key, SMB3_ENC_DEC_KEY_SIZE);
	spin_lock(&ses->chan_lock);
	if (is_binding)
		memcpy(ses->chans[chan_index].signkey, sign_key, SMB3_SIGN_KEY_SIZE);
	else
		/* safe to access primary channel, since it will never go away */
		memcpy(ses->chans[0].signkey, sign_key, SMB3_SIGN_KEY_SIZE);
	spin_unlock(&ses->chan_lock);
	memcpy(ses->smb3signingkey, sign_key, SMB3_SIGN_KEY_SIZE);

	cifs_dbg(VFS, "%s: dumping generated AES session keys\n", __func__);
	/*
	 * The session id is opaque in terms of endianness, so we can't
	 * print it as a long long. we dump it as we got it on the wire
	 */
	cifs_dbg(VFS, "Session Id    %*ph\n", (int)sizeof(ses->Suid),
			&ses->Suid);
	cifs_dbg(VFS, "Cipher type   %d\n", server->cipher_type);
	cifs_dbg(VFS, "Session Key   %*ph\n",
		 SMB2_NTLMV2_SESSKEY_SIZE, ses->auth_key.response);
	cifs_dbg(VFS, "Signing Key   %*ph\n",
		 SMB3_SIGN_KEY_SIZE, ses->smb3signingkey);
	if ((server->cipher_type == SMB2_ENCRYPTION_AES256_CCM) ||
		(server->cipher_type == SMB2_ENCRYPTION_AES256_GCM)) {
		cifs_dbg(VFS, "ServerIn Key  %*ph\n",
				SMB3_GCM256_CRYPTKEY_SIZE, ses->smb3encryptionkey);
		cifs_dbg(VFS, "ServerOut Key %*ph\n",
				SMB3_GCM256_CRYPTKEY_SIZE, ses->smb3decryptionkey);
	} else {
		cifs_dbg(VFS, "ServerIn Key  %*ph\n",
				SMB3_GCM128_CRYPTKEY_SIZE, ses->smb3encryptionkey);
		cifs_dbg(VFS, "ServerOut Key %*ph\n",
				SMB3_GCM128_CRYPTKEY_SIZE, ses->smb3decryptionkey);
	}
#endif
	memzero_explicit(sign_key, SMB3_SIGN_KEY_SIZE);
	memzero_explicit(enc_key, SMB3_ENC_DEC_KEY_SIZE);
	memzero_explicit(dec_key, SMB3_ENC_DEC_KEY_SIZE);
	return rc;
}

int
generate_smb30signingkey(struct cifs_ses *ses,
			 struct TCP_Server_Info *server)

{
	struct derivation_triplet triplet;
	struct derivation *d;

	d = &triplet.signing;
	d->label.iov_base = "SMB2AESCMAC";
	d->label.iov_len = 12;
	d->context.iov_base = "SmbSign";
	d->context.iov_len = 8;

	d = &triplet.encryption;
	d->label.iov_base = "SMB2AESCCM";
	d->label.iov_len = 11;
	d->context.iov_base = "ServerIn ";
	d->context.iov_len = 10;

	d = &triplet.decryption;
	d->label.iov_base = "SMB2AESCCM";
	d->label.iov_len = 11;
	d->context.iov_base = "ServerOut";
	d->context.iov_len = 10;

	return generate_smb3signingkey(ses, server, &triplet);
}

int
generate_smb311signingkey(struct cifs_ses *ses,
			  struct TCP_Server_Info *server)

{
	struct derivation_triplet triplet;
	struct derivation *d;

	d = &triplet.signing;
	d->label.iov_base = "SMBSigningKey";
	d->label.iov_len = 14;
	d->context.iov_base = ses->preauth_sha_hash;
	d->context.iov_len = 64;

	d = &triplet.encryption;
	d->label.iov_base = "SMBC2SCipherKey";
	d->label.iov_len = 16;
	d->context.iov_base = ses->preauth_sha_hash;
	d->context.iov_len = 64;

	d = &triplet.decryption;
	d->label.iov_base = "SMBS2CCipherKey";
	d->label.iov_len = 16;
	d->context.iov_base = ses->preauth_sha_hash;
	d->context.iov_len = 64;

	return generate_smb3signingkey(ses, server, &triplet);
}

/*
 * This function implements AES-GMAC signing for SMB2 messages as described in MS-SMB2
 * specification.  This algorithm is only supported on SMB 3.1.1.
 *
 * Note: even though Microsoft mentions RFC4543 in MS-SMB2, the mechanism used _must_ be the "raw"
 * AES-128-GCM.  RFC4543 is designed for IPsec Encapsulating Security Payload (ESP) and
 * Authentication Header (AH).  Trying to use "rfc4543(gcm(aes)))" as the AEAD algorithm will fail
 * the signature computation.
 *
 * References:
 * MS-SMB2 3.1.4.1 "Signing An Outgoing Message"
 */
int
smb311_calc_signature(struct smb_rqst *rqst, struct TCP_Server_Info *server, bool verify)
{
	union {
		struct {
			/* for MessageId (8 bytes) */
			__le64 mid;
			/* for role (client or server) and if SMB2 CANCEL (4 bytes) */
			__le32 role;
		};
		u8 buffer[12];
	} __packed nonce;
	u8 sig[SMB2_SIGNATURE_SIZE] = { 0 };
	struct aead_request *aead_req = NULL;
	struct crypto_aead *tfm = NULL;
	struct scatterlist *sg = NULL;
	unsigned long assoclen;
	struct smb2_hdr *shdr = NULL;
	struct crypto_wait *wait;
	unsigned int save_npages = 0;
	int rc = 0;

	if (verify) {
		wait = &server->secmech.verify_wait;
		tfm = server->secmech.verify.aead;
	} else {
		wait = &server->secmech.sign_wait;
		tfm = server->secmech.sign.aead;
	}

	if (completion_done(&wait->completion))
		reinit_completion(&wait->completion);

	shdr = (struct smb2_hdr *)rqst->rq_iov[0].iov_base;

	memset(shdr->Signature, 0, SMB2_SIGNATURE_SIZE);
	memset(&nonce, 0, SMB3_AES_GCM_NONCE);

	/* note that nonce must always be little endian */
	nonce.mid = shdr->MessageId;
	/* request is coming from the server, set LSB */
	nonce.role |= shdr->Flags & SMB2_FLAGS_SERVER_TO_REDIR;
	/* set penultimate LSB if SMB2_CANCEL command */
	if (shdr->Command == SMB2_CANCEL)
		nonce.role |= cpu_to_le32(1UL << 1);

	aead_req = aead_request_alloc(tfm, GFP_KERNEL);
	if (!aead_req) {
		cifs_dbg(VFS, "%s: Failed to alloc AEAD request\n", __func__);
		return -ENOMEM;
	}

	/* skip page data if non-success error status, as it will compute an invalid signature */
	if (shdr->Status != 0 && rqst->rq_npages > 0) {
		save_npages = rqst->rq_npages;
		rqst->rq_npages = 0;
	}

	assoclen = smb_rqst_len(server, rqst);

	sg = smb3_init_sg(1, rqst, sig);
	if (!sg) {
		cifs_dbg(VFS, "%s: Failed to init SG\n", __func__);
		goto out_free_req;
	}

	/* cryptlen == 0 because we're not encrypting anything */
	aead_request_set_crypt(aead_req, sg, sg, 0, nonce.buffer);
	aead_request_set_ad(aead_req, assoclen);
	aead_request_set_callback(aead_req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, wait);

	/*
	 * Reminder: we must always use the encrypt function, as AES-GCM decrypt will internally
	 * try to match the authentication codes, where we pass a zeroed buffer, and the operation
	 * will fail (-EBADMSG) (expectedly).
	 *
	 * Also note we can't use crypto_wait_req() here since it's not interruptible.
	 */
	rc = crypto_aead_encrypt(aead_req);
	if (!rc)
		goto out;

	if (rc == -EINPROGRESS || rc == -EBUSY) {
		rc = wait_for_completion_interruptible(&wait->completion);
		if (!rc)
			/* wait->err is set by crypto_req_done callback above */
			rc = wait->err;
	}

	if (rc) {
		cifs_server_dbg(VFS, "%s: Failed to compute AES-GMAC signature, rc=%d\n",
				__func__, rc);
		goto out_free_sg;
	}

out:
	memcpy(&shdr->Signature, sig, SMB2_SIGNATURE_SIZE);
out_free_sg:
	kfree(sg);
out_free_req:
	kfree(aead_req);

	/* restore rq_npages for further processing */
	if (shdr->Status != 0 && save_npages > 0)
		rqst->rq_npages = save_npages;

	return rc;
}

/* must be called with server->srv_mutex held */
static int
smb2_sign_rqst(struct smb_rqst *rqst, struct TCP_Server_Info *server)
{
	int rc = 0;
	struct smb2_hdr *shdr;
	struct smb2_sess_setup_req *ssr;
	bool is_binding;
	bool is_signed;

	shdr = (struct smb2_hdr *)rqst->rq_iov[0].iov_base;
	ssr = (struct smb2_sess_setup_req *)shdr;

	is_binding = shdr->Command == SMB2_SESSION_SETUP &&
		(ssr->Flags & SMB2_SESSION_REQ_FLAG_BINDING);
	is_signed = shdr->Flags & SMB2_FLAGS_SIGNED;

	if (!is_signed)
		return 0;
	spin_lock(&server->srv_lock);
	if (server->ops->need_neg &&
	    server->ops->need_neg(server)) {
		spin_unlock(&server->srv_lock);
		return 0;
	}
	spin_unlock(&server->srv_lock);
	if (!is_binding && !server->session_estab)
		return 0;

	rc = server->secmech.calc_signature(rqst, server, false);

	return rc;
}

int
smb2_verify_signature(struct smb_rqst *rqst, struct TCP_Server_Info *server)
{
	unsigned int rc;
	char server_response_sig[SMB2_SIGNATURE_SIZE];
	struct smb2_hdr *shdr =
			(struct smb2_hdr *)rqst->rq_iov[0].iov_base;

	if ((shdr->Command == SMB2_NEGOTIATE) ||
	    (shdr->Command == SMB2_SESSION_SETUP) ||
	    (shdr->Command == SMB2_OPLOCK_BREAK) ||
	    (shdr->MessageId == cpu_to_le64(0xFFFFFFFFFFFFFFFF)) || /* MS-SMB2 3.2.5.1.3 */
	    (shdr->Status == STATUS_PENDING) || /* MS-SMB2 3.2.5.1.3 */
	    server->ignore_signature ||
	    (!server->session_estab))
		return 0;

	/*
	 * BB what if signatures are supposed to be on for session but
	 * server does not send one? BB
	 */

	/*
	 * Save off the origiginal signature so we can modify the smb and check
	 * our calculated signature against what the server sent.
	 */
	memcpy(server_response_sig, shdr->Signature, SMB2_SIGNATURE_SIZE);

	rc = server->secmech.calc_signature(rqst, server, true);

	if (rc)
		return rc;

	if (memcmp(server_response_sig, shdr->Signature, SMB2_SIGNATURE_SIZE)) {
		cifs_dbg(VFS, "sign fail cmd 0x%x message id 0x%llx\n",
			shdr->Command, shdr->MessageId);
		return -EACCES;
	} else
		return 0;
}

/*
 * Set message id for the request. Should be called after wait_for_free_request
 * and when srv_mutex is held.
 */
static inline void
smb2_seq_num_into_buf(struct TCP_Server_Info *server,
		      struct smb2_hdr *shdr)
{
	unsigned int i, num = le16_to_cpu(shdr->CreditCharge);

	shdr->MessageId = get_next_mid64(server);
	/* skip message numbers according to CreditCharge field */
	for (i = 1; i < num; i++)
		get_next_mid(server);
}

static struct mid_q_entry *
smb2_mid_entry_alloc(const struct smb2_hdr *shdr,
		     struct TCP_Server_Info *server)
{
	struct mid_q_entry *temp;
	unsigned int credits = le16_to_cpu(shdr->CreditCharge);

	if (server == NULL) {
		cifs_dbg(VFS, "Null TCP session in smb2_mid_entry_alloc\n");
		return NULL;
	}

	temp = mempool_alloc(cifs_mid_poolp, GFP_NOFS);
	memset(temp, 0, sizeof(struct mid_q_entry));
	kref_init(&temp->refcount);
	temp->mid = le64_to_cpu(shdr->MessageId);
	temp->credits = credits > 0 ? credits : 1;
	temp->pid = current->pid;
	temp->command = shdr->Command; /* Always LE */
	temp->when_alloc = jiffies;
	temp->server = server;

	/*
	 * The default is for the mid to be synchronous, so the
	 * default callback just wakes up the current task.
	 */
	get_task_struct(current);
	temp->creator = current;
	temp->callback = cifs_wake_up_task;
	temp->callback_data = current;

	atomic_inc(&mid_count);
	temp->mid_state = MID_REQUEST_ALLOCATED;
	trace_smb3_cmd_enter(le32_to_cpu(shdr->Id.SyncId.TreeId),
			     le64_to_cpu(shdr->SessionId),
			     le16_to_cpu(shdr->Command), temp->mid);
	return temp;
}

static int
smb2_get_mid_entry(struct cifs_ses *ses, struct TCP_Server_Info *server,
		   struct smb2_hdr *shdr, struct mid_q_entry **mid)
{
	spin_lock(&server->srv_lock);
	if (server->tcpStatus == CifsExiting) {
		spin_unlock(&server->srv_lock);
		return -ENOENT;
	}

	if (server->tcpStatus == CifsNeedReconnect) {
		spin_unlock(&server->srv_lock);
		cifs_dbg(FYI, "tcp session dead - return to caller to retry\n");
		return -EAGAIN;
	}

	if (server->tcpStatus == CifsNeedNegotiate &&
	   shdr->Command != SMB2_NEGOTIATE) {
		spin_unlock(&server->srv_lock);
		return -EAGAIN;
	}
	spin_unlock(&server->srv_lock);

	spin_lock(&ses->ses_lock);
	if (ses->ses_status == SES_NEW) {
		if ((shdr->Command != SMB2_SESSION_SETUP) &&
		    (shdr->Command != SMB2_NEGOTIATE)) {
			spin_unlock(&ses->ses_lock);
			return -EAGAIN;
		}
		/* else ok - we are setting up session */
	}

	if (ses->ses_status == SES_EXITING) {
		if (shdr->Command != SMB2_LOGOFF) {
			spin_unlock(&ses->ses_lock);
			return -EAGAIN;
		}
		/* else ok - we are shutting down the session */
	}
	spin_unlock(&ses->ses_lock);

	*mid = smb2_mid_entry_alloc(shdr, server);
	if (*mid == NULL)
		return -ENOMEM;
	spin_lock(&server->mid_lock);
	list_add_tail(&(*mid)->qhead, &server->pending_mid_q);
	spin_unlock(&server->mid_lock);

	return 0;
}

int
smb2_check_receive(struct mid_q_entry *mid, struct TCP_Server_Info *server,
		   bool log_error)
{
	unsigned int len = mid->resp_buf_size;
	struct kvec iov[1];
	struct smb_rqst rqst = { .rq_iov = iov,
				 .rq_nvec = 1 };

	iov[0].iov_base = (char *)mid->resp_buf;
	iov[0].iov_len = len;

	dump_smb(mid->resp_buf, min_t(u32, 80, len));
	/* convert the length into a more usable form */
	if (len > 24 && server->sign && !mid->decrypted) {
		int rc;

		rc = smb2_verify_signature(&rqst, server);
		if (rc)
			cifs_server_dbg(VFS, "SMB signature verification returned error = %d\n",
				 rc);
	}

	return map_smb2_to_linux_error(mid->resp_buf, log_error);
}

struct mid_q_entry *
smb2_setup_request(struct cifs_ses *ses, struct TCP_Server_Info *server,
		   struct smb_rqst *rqst)
{
	int rc;
	struct smb2_hdr *shdr =
			(struct smb2_hdr *)rqst->rq_iov[0].iov_base;
	struct smb2_transform_hdr *trhdr =
			(struct smb2_transform_hdr *)rqst->rq_iov[0].iov_base;
	struct mid_q_entry *mid;

	smb2_seq_num_into_buf(server, shdr);

	rc = smb2_get_mid_entry(ses, server, shdr, &mid);
	if (rc) {
		revert_current_mid_from_hdr(server, shdr);
		return ERR_PTR(rc);
	}

	/*
	 * Client must not sign the request if it's encrypted.
	 *
	 * Note: we can't rely on SMB2_SESSION_FLAG_ENCRYPT_DATA or SMB2_GLOBAL_CAP_ENCRYPTION
	 * here because they might be set, but not being actively used (e.g. not mounted with
	 * "seal"), so just check if header is a transform header.
	 *
	 * References:
	 * MS-SMB2 3.2.4.1.1
	 */
	if (trhdr->ProtocolId != SMB2_TRANSFORM_PROTO_NUM) {
		rc = smb2_sign_rqst(rqst, server);
		if (rc) {
			revert_current_mid_from_hdr(server, shdr);
			delete_mid(mid);
			return ERR_PTR(rc);
		}
	}

	return mid;
}

struct mid_q_entry *
smb2_setup_async_request(struct TCP_Server_Info *server, struct smb_rqst *rqst)
{
	int rc;
	struct smb2_hdr *shdr =
			(struct smb2_hdr *)rqst->rq_iov[0].iov_base;
	struct mid_q_entry *mid;

	spin_lock(&server->srv_lock);
	if (server->tcpStatus == CifsNeedNegotiate &&
	   shdr->Command != SMB2_NEGOTIATE) {
		spin_unlock(&server->srv_lock);
		return ERR_PTR(-EAGAIN);
	}
	spin_unlock(&server->srv_lock);

	smb2_seq_num_into_buf(server, shdr);

	mid = smb2_mid_entry_alloc(shdr, server);
	if (mid == NULL) {
		revert_current_mid_from_hdr(server, shdr);
		return ERR_PTR(-ENOMEM);
	}

	rc = smb2_sign_rqst(rqst, server);
	if (rc) {
		revert_current_mid_from_hdr(server, shdr);
		release_mid(mid);
		return ERR_PTR(rc);
	}

	return mid;
}

int
smb3_crypto_aead_allocate(const char *name, struct crypto_aead **tfm)
{
	if (unlikely(!tfm))
		return -EIO;

	if (*tfm)
		return 0;

	if (unlikely(!name))
		return -EINVAL;

	if (unlikely(strcmp(name, "gcm(aes)") && strcmp(name, "ccm(aes)"))) {
		cifs_dbg(VFS, "%s: crypto API '%s' is unsupported in cifs.ko\n", __func__, name);
		return -EOPNOTSUPP;
	}

	*tfm = crypto_alloc_aead(name, CRYPTO_ALG_TYPE_AEAD, 0);
	if (IS_ERR(*tfm)) {
		cifs_dbg(VFS, "%s: Failed to alloc %s crypto TFM, rc=%ld\n",
			 __func__, name, PTR_ERR(*tfm));
		return PTR_ERR(*tfm);
	}

	return 0;
}

void smb3_crypto_aead_free(struct crypto_aead **tfm)
{
	if (!tfm || !*tfm)
		return;

	crypto_free_aead(*tfm);
	*tfm = NULL;
}
