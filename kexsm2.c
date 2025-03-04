#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <string.h>
#include <openssl/ecdh.h>
#include <openssl/ec.h>

int sm2_compute_z_digest(uint8_t *out,
                         const EVP_MD *digest,
                         const uint8_t *id,
                         const size_t id_len,
                         const EC_KEY *key)
{
    int rc = 0;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    BN_CTX *ctx = NULL;
    EVP_MD_CTX *hash = NULL;
    BIGNUM *p = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *xG = NULL;
    BIGNUM *yG = NULL;
    BIGNUM *xA = NULL;
    BIGNUM *yA = NULL;
    int p_bytes = 0;
    uint8_t *buf = NULL;
    uint16_t entl = 0;
    uint8_t e_byte = 0;

    hash = EVP_MD_CTX_new();
    ctx = BN_CTX_new();
    if (hash == NULL || ctx == NULL) {
        goto done;
    }

    p = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    xG = BN_CTX_get(ctx);
    yG = BN_CTX_get(ctx);
    xA = BN_CTX_get(ctx);
    yA = BN_CTX_get(ctx);

    if (yA == NULL) {
        goto done;
    }

    if (!EVP_DigestInit(hash, digest)) {
        goto done;
    }

    /* Z = h(ENTL || ID || a || b || xG || yG || xA || yA) */

    if (id_len >= (UINT16_MAX / 8)) {
        /* too large */
        goto done;
    }

    entl = (uint16_t)(8 * id_len);

    e_byte = entl >> 8;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        goto done;
    }
    e_byte = entl & 0xFF;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        goto done;
    }

    if (id_len > 0 && !EVP_DigestUpdate(hash, id, id_len)) {
        goto done;
    }

    if (!EC_GROUP_get_curve(group, p, a, b, ctx)) {
        goto done;
    }

    p_bytes = BN_num_bytes(p);
    buf = OPENSSL_zalloc(p_bytes);
    if (buf == NULL) {
        goto done;
    }

    if (BN_bn2binpad(a, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || BN_bn2binpad(b, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || !EC_POINT_get_affine_coordinates(group,
                                                EC_GROUP_get0_generator(group),
                                                xG, yG, ctx)
            || BN_bn2binpad(xG, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || BN_bn2binpad(yG, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || !EC_POINT_get_affine_coordinates(group,
                                                EC_KEY_get0_public_key(key),
                                                xA, yA, ctx)
            || BN_bn2binpad(xA, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || BN_bn2binpad(yA, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || !EVP_DigestFinal(hash, out, NULL)) {
        goto done;
    }

    rc = 1;

 done:
    OPENSSL_free(buf);
    BN_CTX_free(ctx);
    EVP_MD_CTX_free(hash);
    return rc;
}

/* GM/T003_2012 Defined Key Derive Function */
int kdf_gmt003_2012(unsigned char *out, size_t outlen, const unsigned char *Z, size_t Zlen, const unsigned char *SharedInfo, size_t SharedInfolen, const EVP_MD *md)
{
    EVP_MD_CTX *mctx = NULL;
    unsigned int counter;
    unsigned char ctr[4];
    size_t mdlen;
    int retval = 0;
    unsigned char dgst[EVP_MAX_MD_SIZE];

    if (!out || !outlen) return retval;
    if (md == NULL) {
        md = EVP_sm3();
    }
    mdlen = EVP_MD_size(md);
    mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        goto err;
    }

    for (counter = 1;; counter++) {
        if (!EVP_DigestInit(mctx, md)) {
            goto err;
        }
        ctr[0] = (unsigned char)((counter >> 24) & 0xFF);
        ctr[1] = (unsigned char)((counter >> 16) & 0xFF);
        ctr[2] = (unsigned char)((counter >> 8) & 0xFF);
        ctr[3] = (unsigned char)(counter & 0xFF);

        if (!EVP_DigestUpdate(mctx, Z, Zlen)) {
            goto err;
        }
        if (!EVP_DigestUpdate(mctx, ctr, sizeof(ctr))) {
            goto err;
        }
        if (!EVP_DigestUpdate(mctx, SharedInfo, SharedInfolen)) {
            goto err;
        }
        if (!EVP_DigestFinal(mctx, dgst, NULL)) {
            goto err;
        }

        if (outlen > mdlen) {
            memcpy(out, dgst, mdlen);
            out += mdlen;
            outlen -= mdlen;
        } else {
            memcpy(out, dgst, outlen);
            memset(dgst, 0, mdlen);
            break;
        }
    }

    retval = 1;

err:
    EVP_MD_CTX_free(mctx);
    return retval;
}

int sm2_kap_compute_key(void *out, size_t outlen, int server,
    const uint8_t *peer_uid, int peer_uid_len, const uint8_t *self_uid, int self_uid_len, 
    const EC_KEY *peer_ecdhe_key, const EC_KEY *self_ecdhe_key, const EC_KEY *peer_pub_key, const EC_KEY *self_eckey, 
    const EVP_MD *md)
{
    BN_CTX *ctx = NULL;
    EC_POINT *UorV = NULL;
    const EC_POINT *Rs, *Rp;
    BIGNUM *Xs = NULL, *Xp = NULL, *h = NULL, *t = NULL, *two_power_w = NULL, *order = NULL;
    const BIGNUM *priv_key, *r;
    const EC_GROUP *group;
    int w;
    int ret = -1;
    size_t buflen, len;
    unsigned char *buf = NULL;

    if (outlen > INT_MAX) {
        goto err;
    }

    if (!peer_pub_key || !self_eckey) {
        goto err;
    }

    priv_key = EC_KEY_get0_private_key(self_eckey);
    if (!priv_key) {
        goto err;
    }

    if (!peer_ecdhe_key || !self_ecdhe_key) {
        goto err;
    }

    Rs = EC_KEY_get0_public_key(self_ecdhe_key);
    Rp = EC_KEY_get0_public_key(peer_ecdhe_key);
    r = EC_KEY_get0_private_key(self_ecdhe_key);

    if (!Rs || !Rp || !r) {
        goto err;
    }

    ctx = BN_CTX_new();
    Xs = BN_new();
    Xp = BN_new();
    h = BN_new();
    t = BN_new();
    two_power_w = BN_new();
    order = BN_new();
    if (!Xs || !Xp || !h || !t || !two_power_w || !order) {
        goto err;
    }

    group = EC_KEY_get0_group(self_eckey);

    /*Second: Caculate -- w*/
    if (!EC_GROUP_get_order(group, order, ctx) || !EC_GROUP_get_cofactor(group, h, ctx)) {
        goto err;
    }

    w = (BN_num_bits(order) + 1) / 2 - 1;
    if (!BN_lshift(two_power_w, BN_value_one(), w)) {
        goto err;
    }

/*Third: Calculate -- X =  2 ^ w + (x & (2 ^ w - 1)) = 2 ^ w + (x mod 2 ^ w)*/
UorV = EC_POINT_new(group);

if (!UorV) {
    goto err;
}

/*Test peer public key On curve*/
if (!EC_POINT_is_on_curve(group, Rp, ctx)) {
    goto err;
}

/*Get x*/
if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
    if (!EC_POINT_get_affine_coordinates_GFp(group, Rs, Xs, NULL, ctx)) {
        goto err;
    }

    if (!EC_POINT_get_affine_coordinates_GFp(group, Rp, Xp, NULL, ctx)) {
        goto err;
    }
}

/*x mod 2 ^ w*/
/*Calculate Self x*/
if (!BN_nnmod(Xs, Xs, two_power_w, ctx)) {
    goto err;
}

if (!BN_add(Xs, Xs, two_power_w)) {
    goto err;
}

/*Calculate Peer x*/
if (!BN_nnmod(Xp, Xp, two_power_w, ctx)) {
    goto err;
}

if (!BN_add(Xp, Xp, two_power_w)) {
    goto err;
}

/*Forth: Calculate t*/
if (!BN_mod_mul(t, Xs, r, order, ctx)) {
    goto err;
}

if (!BN_mod_add(t, t, priv_key, order, ctx)) {
    goto err;
}

/*Fifth: Calculate V or U*/
if (!BN_mul(t, t, h, ctx)) {
    goto err;
}

/* [x]R */
if (!EC_POINT_mul(group, UorV, NULL, Rp, Xp, ctx)) {
    goto err;
}

/* P + [x]R */
if (!EC_POINT_add(group, UorV, UorV, EC_KEY_get0_public_key(peer_pub_key), ctx)) {
    goto err;
}

if (!EC_POINT_mul(group, UorV, NULL, UorV, t, ctx)) {
    goto err;
}

/* Detect UorV is in */
if (EC_POINT_is_at_infinity(group, UorV)) {
    goto err;
}

/*Sixth: Calculate Key -- Need Xuorv, Yuorv, Zc, Zs, klen*/
{
    size_t elemet_len, idx;

    elemet_len = (size_t)((EC_GROUP_get_degree(group) + 7) / 8);
    buflen = elemet_len * 2 + 32 * 2 + 1;    /*add 1 byte tag*/
    buf = (unsigned char *)OPENSSL_malloc(buflen + 10);
    if (!buf) {
        goto err;
    }
    memset(buf, 0, buflen + 10);
    /*1 : Get public key for UorV, Notice: the first byte is a tag, not a valid char*/
    idx = EC_POINT_point2oct(group, UorV, 4, buf, buflen, ctx);
    if (!idx) {
        goto err;
    }

        if (!server) {
            /*SIDE A*/
            len = buflen - idx;
            if (!sm2_compute_z_digest( (unsigned char *)(buf + idx), md, (const uint8_t *)self_uid, self_uid_len, self_eckey)) {
                goto err;
            }
            len = 32;
            idx += len;
        }

        /*Caculate Peer Z*/
        len = buflen - idx;
        if (!sm2_compute_z_digest( (unsigned char *)(buf + idx), md, (const uint8_t *)peer_uid, peer_uid_len, peer_pub_key)) {
            goto err;
        }
        len = 32;
        idx += len;

        if (server) {
            /*SIDE B*/
            len = buflen - idx;
            if (!sm2_compute_z_digest( (unsigned char *)(buf + idx), md, (const uint8_t *)self_uid, self_uid_len, self_eckey)) {
                goto err;
            }
            len = 32;
            idx += len;
        }

        len = outlen;
        if (!kdf_gmt003_2012(out, len, (const unsigned char *)(buf + 1), idx - 1, NULL, 0, md)) {
            goto err;
        }
    }

    ret = outlen;

err:
    if (Xs) BN_free(Xs);
    if (Xp) BN_free(Xp);
    if (h) BN_free(h);
    if (t) BN_free(t);
    if (two_power_w) BN_free(two_power_w);
    if (order) BN_free(order);
    if (UorV) EC_POINT_free(UorV);
    if (buf) OPENSSL_free(buf);
    if (ctx) BN_CTX_free(ctx);

    return ret;
}

int SM2KAP_compute_key(void *out, size_t outlen, const EC_POINT *pub_key, const EC_KEY *eckey, int server)
{
	int ret = 0;
	EC_KEY *pubkey = NULL;
	unsigned char id[16] = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};

	if ((pubkey = EC_KEY_new_by_curve_name(NID_sm2)) == NULL) {
		return ret;
	}

	if (EC_KEY_set_public_key(pubkey, pub_key) != 1) {
		ret = 0;
		goto out;
	}

	ret = sm2_kap_compute_key(out, outlen, server, id, sizeof(id), id, sizeof(id), pubkey, eckey, pubkey, eckey, (EVP_MD*)EVP_sm3());

out:
	EC_KEY_free(pubkey);
	return ret;
}

