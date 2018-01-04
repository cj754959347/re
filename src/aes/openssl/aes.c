/**
 * @file openssl/aes.c  AES (Advanced Encryption Standard) using OpenSSL
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <re_types.h>
#include <re_fmt.h>
#include <re_mem.h>
#include <re_aes.h>


#ifdef EVP_CIPH_CTR_MODE


struct aes {
	EVP_CIPHER_CTX *ctx;
	enum aes_mode mode;
};


static void destructor(void *arg)
{
	struct aes *st = arg;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	if (st->ctx)
		EVP_CIPHER_CTX_free(st->ctx);
#else
	if (st->ctx)
		EVP_CIPHER_CTX_cleanup(st->ctx);
	mem_deref(st->ctx);
#endif
}


int aes_alloc(struct aes **aesp, enum aes_mode mode,
	      const uint8_t *key, size_t key_bits,
	      const uint8_t iv[AES_BLOCK_SIZE])
{
	const EVP_CIPHER *cipher;
	struct aes *st;
	int err = 0, r;

	if (!aesp || !key)
		return EINVAL;

	st = mem_zalloc(sizeof(*st), destructor);
	if (!st)
		return ENOMEM;

	st->mode = mode;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	st->ctx = EVP_CIPHER_CTX_new();
	if (!st->ctx) {
		ERR_clear_error();
		err = ENOMEM;
		goto out;
	}

#else
	st->ctx = mem_zalloc(sizeof(*st->ctx), NULL);
	if (!st->ctx) {
		err = ENOMEM;
		goto out;
	}

	EVP_CIPHER_CTX_init(st->ctx);
#endif

	if (mode == AES_MODE_CTR) {

		switch (key_bits) {

		case 128: cipher = EVP_aes_128_ctr(); break;
		case 192: cipher = EVP_aes_192_ctr(); break;
		case 256: cipher = EVP_aes_256_ctr(); break;
		default:
			re_fprintf(stderr, "aes: ctr: unknown key: %zu bits\n",
				   key_bits);
			err = EINVAL;
			goto out;
		}
	}
	else if (mode == AES_MODE_GCM) {

		switch (key_bits) {

		case 128: cipher = EVP_aes_128_gcm(); break;
		case 256: cipher = EVP_aes_256_gcm(); break;
		default:
			re_fprintf(stderr, "aes: gcm: unknown key: %zu bits\n",
				   key_bits);
			err = EINVAL;
			goto out;
		}
	}
	else {
		re_fprintf(stderr, "aes: unknown mode: %d\n", mode);
		err = EINVAL;
		goto out;
	}

	r = EVP_EncryptInit_ex(st->ctx, cipher, NULL, key, iv);
	if (!r) {
		ERR_clear_error();
		err = EPROTO;
	}

 out:
	if (err)
		mem_deref(st);
	else
		*aesp = st;

	return err;
}


void aes_set_iv(struct aes *aes, const uint8_t iv[AES_BLOCK_SIZE])
{
	int r;

	if (!aes || !iv)
		return;

	r = EVP_EncryptInit_ex(aes->ctx, NULL, NULL, NULL, iv);
	if (!r)
		ERR_clear_error();
}


int aes_encr(struct aes *aes, uint8_t *out, const uint8_t *in, size_t len)
{
	int c_len = (int)len;

	if (!aes || !out || !in)
		return EINVAL;

	if (aes->mode != AES_MODE_CTR)
		return ENOTSUP;

	if (!EVP_EncryptUpdate(aes->ctx, out, &c_len, in, (int)len)) {
		ERR_clear_error();
		return EPROTO;
	}

	return 0;
}


/**
 * Add (append) any AAD (Additional Authenticated Data) bytes.
 *
 * This can be called zero or more times as required
 *
 * @note Only valid for AEAD ciphers
 *
 * @param aes     AES context
 * @param aad     Additional Authenticated Data (AAD)
 * @param aad_len Number of AAD bytes
 *
 * @return 0 if success, otherwise errorcode
 */
int aes_add_aad(struct aes *aes, const uint8_t *aad, size_t aad_len)
{
	int tmplen;

	if (!aes || !aad || !aad_len)
		return EINVAL;

	switch (aes->mode) {

	case AES_MODE_GCM:
		break;
	default:
		return ENOTSUP;
	}

	if (!EVP_CipherUpdate(aes->ctx, NULL, &tmplen, aad, (int)aad_len)) {
		ERR_clear_error();
		return EPROTO;
	}

	(void)tmplen;  /* not used */

	return 0;
}


/**
 * Perform authenticated encryption using an AEAD cipher
 *
 * @param aes    AES Context
 * @param out    Encrypted output
 * @param tag    Authentication tag
 * @param taglen Length of Authentication tag
 * @param in     Plaintext input (optional)
 * @param len    Length of plaintext input (optional)
 *
 * @return 0 if success, otherwise errorcode
 */
int aes_auth_encr(struct aes *aes, uint8_t *out, uint8_t *tag, size_t taglen,
		  const uint8_t *in, size_t len)
{
	int c_len = (int)len;
	int tmplen;

	if (!aes || !out || !in)
		return EINVAL;

	if (aes->mode != AES_MODE_GCM)
		return ENOTSUP;

	/* update the encrypt/decrypt direction */
	if (!EVP_CipherInit_ex(aes->ctx, NULL, NULL, NULL, NULL, true))
		goto error;

	if (!EVP_EncryptUpdate(aes->ctx, out, &c_len, in, (int)len))
		goto error;

	if (!EVP_EncryptFinal_ex(aes->ctx, NULL, &tmplen))
		goto error;

	(void)tmplen;  /* not used */

	if (tag && taglen) {

		if (!EVP_CIPHER_CTX_ctrl(aes->ctx, EVP_CTRL_GCM_GET_TAG,
					 (int)taglen, tag))
			goto error;
	}

	return 0;

 error:
	ERR_clear_error();
	return EPROTO;
}


/**
 * Perform authenticated decryption using an AEAD cipher
 *
 * @param aes    AES Context
 * @param out    Plaintext output
 * @param in     Encrypted input (optional)
 * @param len    Length of encrypted input (optional)
 * @param tag    Authentication tag
 * @param taglen Length of Authentication tag
 *
 * @return 0 if success, otherwise errorcode
 *
 * @retval EAUTH if authentication failed
 */
int aes_auth_decr(struct aes *aes, uint8_t *out, const uint8_t *in, size_t len,
		  const uint8_t *tag, size_t taglen)
{
	int c_len = (int)len;
	int outlen;

	if (!aes || !out || !in || !tag || !taglen)
		return EINVAL;

	if (aes->mode != AES_MODE_GCM)
		return ENOTSUP;

	/* update the encrypt/decrypt direction */
	if (!EVP_CipherInit_ex(aes->ctx, NULL, NULL, NULL, NULL, false))
		goto error;

	if (!EVP_DecryptUpdate(aes->ctx, out, &c_len, in, (int)len))
		goto error;

	/* Set expected tag value. */
	if (!EVP_CIPHER_CTX_ctrl(aes->ctx, EVP_CTRL_GCM_SET_TAG,
				 (int)taglen, (void *)tag))
		goto error;

	if (EVP_DecryptFinal_ex(aes->ctx, NULL, &outlen) <= 0)
		return EAUTH;

	(void)outlen;  /* not used */

	return 0;

 error:
	ERR_clear_error();
	return EPROTO;
}


#else /* EVP_CIPH_CTR_MODE */


struct aes {
	AES_KEY key;
	uint8_t iv[AES_BLOCK_SIZE];
};


static void destructor(void *arg)
{
	struct aes *st = arg;

	memset(&st->key, 0, sizeof(st->key));
}


int aes_alloc(struct aes **aesp, enum aes_mode mode,
	      const uint8_t *key, size_t key_bits,
	      const uint8_t iv[AES_BLOCK_SIZE])
{
	struct aes *st;
	int err = 0, r;

	if (!aesp || !key)
		return EINVAL;

	if (mode != AES_MODE_CTR)
		return ENOTSUP;

	st = mem_zalloc(sizeof(*st), destructor);
	if (!st)
		return ENOMEM;

	r = AES_set_encrypt_key(key, (int)key_bits, &st->key);
	if (r != 0) {
		err = EPROTO;
		goto out;
	}
	if (iv)
		memcpy(st->iv, iv, sizeof(st->iv));

 out:
	if (err)
		mem_deref(st);
	else
		*aesp = st;

	return err;
}


void aes_set_iv(struct aes *aes, const uint8_t iv[AES_BLOCK_SIZE])
{
	if (!aes)
		return;

	if (iv)
		memcpy(aes->iv, iv, sizeof(aes->iv));
}


int aes_encr(struct aes *aes, uint8_t *out, const uint8_t *in, size_t len)
{
	unsigned char ec[AES_BLOCK_SIZE] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	unsigned int num = 0;

	if (!aes || !out || !in)
		return EINVAL;

	AES_ctr128_encrypt(in, out, len, &aes->key, aes->iv, ec, &num);

	return 0;
}


#endif /* EVP_CIPH_CTR_MODE */


/*
 * Common code:
 */


int aes_decr(struct aes *aes, uint8_t *out, const uint8_t *in, size_t len)
{
	return aes_encr(aes, out, in, len);
}
