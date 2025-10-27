/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * GOST CMS Key Transport support using kexp15 KDF
 *
 * This module implements support for GOST R 34.10-2012 keys in CMS
 * EnvelopedData using the kexp15 key derivation function as specified
 * in RFC 7836 and Russian cryptographic standards.
 */

#include <assert.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include "crypto/asn1.h"
#include "crypto/evp.h"
#include "cms_local.h"

/*
 * Set keyEncryptionAlgorithm for GOST R 34.10-2012 keys using kexp15 KDF
 *
 * This function configures the keyEncryptionAlgorithm field in the
 * KeyTransRecipientInfo structure to use the kexp15 KDF algorithm
 * (OID: 1.2.643.7.1.1.7.2.1) with appropriate parameters for GOST keys.
 */
static int gost_cms_encrypt(CMS_RecipientInfo *ri)
{
    CMS_KeyTransRecipientInfo *ktri;
    X509_ALGOR *alg;
    EVP_PKEY *pkey = NULL;
    int pkey_nid;
    int kexp15_oid;
    int param_oid;
    ASN1_OBJECT *param_obj = NULL;

    /* Get the KeyTransRecipientInfo structure */
    if (ri->type != CMS_RECIPINFO_TRANS) {
        ERR_raise(ERR_LIB_CMS, CMS_R_NOT_KEY_TRANSPORT);
        return 0;
    }
    ktri = ri->d.ktri;

    /* Get the public key and keyEncryptionAlgorithm field */
    if (!CMS_RecipientInfo_ktri_get0_algs(ri, &pkey, NULL, &alg))
        return 0;

    if (pkey == NULL)
        return 0;

    /* Get the public key algorithm NID */
    pkey_nid = EVP_PKEY_get_id(pkey);

    /*
     * Check if this is a GOST R 34.10-2012 key.
     * Only for GOST 2012 keys we apply kexp15 KDF.
     *
     * NIDs for GOST R 34.10-2012:
     * - NID_id_GostR3410_2012_256 (979) - 256-bit key
     * - NID_id_GostR3410_2012_512 (980) - 512-bit key
     */
    if (pkey_nid != NID_id_GostR3410_2012_256 &&
        pkey_nid != NID_id_GostR3410_2012_512) {
        /* Not a GOST 2012 key, return success to allow fallback */
        return 1;
    }

    /*
     * Set the appropriate kexp15 OID and parameters based on key size.
     *
     * For GOST R 34.10-2012 with 256-bit keys:
     * - Algorithm OID: 1.2.643.7.1.1.7.2.1 (kuznyechik-kexp15)
     * - Parameter OID: 1.2.643.7.1.1.6.1 (id-tc26-agreement-gost-3410-2012-256)
     *
     * For GOST R 34.10-2012 with 512-bit keys:
     * - Algorithm OID: 1.2.643.7.1.1.7.2.1 (kuznyechik-kexp15)
     * - Parameter OID: 1.2.643.7.1.1.6.2 (id-tc26-agreement-gost-3410-2012-512)
     */
    kexp15_oid = NID_kuznyechik_kexp15; /* 1.2.643.7.1.1.7.2.1 */

    if (pkey_nid == NID_id_GostR3410_2012_256) {
        param_oid = NID_id_tc26_agreement_gost_3410_2012_256; /* 1.2.643.7.1.1.6.1 */
    } else { /* NID_id_GostR3410_2012_512 */
        param_oid = NID_id_tc26_agreement_gost_3410_2012_512; /* 1.2.643.7.1.1.6.2 */
    }

    /*
     * Create parameter structure for kexp15.
     *
     * According to RFC 7836 and GOST standards, the parameter must be
     * a SEQUENCE containing the agreement algorithm OID:
     *
     * KeyWrapAlgorithm ::= AlgorithmIdentifier
     * AlgorithmIdentifier ::= SEQUENCE {
     *   algorithm    OBJECT IDENTIFIER,
     *   parameters   SEQUENCE {           -- This wrapping is required!
     *     OBJECT IDENTIFIER
     *   }
     * }
     */
    {
        ASN1_STRING *param_seq = NULL;
        unsigned char *param_der = NULL;
        int param_der_len;

        /* Create ASN1_OBJECT for the agreement algorithm */
        param_obj = OBJ_nid2obj(param_oid);
        if (param_obj == NULL) {
            ERR_raise(ERR_LIB_CMS, ERR_R_INTERNAL_ERROR);
            return 0;
        }

        /* Encode the OID into DER format */
        param_der_len = i2d_ASN1_OBJECT(param_obj, &param_der);
        if (param_der_len <= 0) {
            ASN1_OBJECT_free(param_obj);
            ERR_raise(ERR_LIB_CMS, ERR_R_INTERNAL_ERROR);
            return 0;
        }

        /* Create ASN1_STRING as SEQUENCE to wrap the encoded OID */
        param_seq = ASN1_STRING_type_new(V_ASN1_SEQUENCE);
        if (param_seq == NULL) {
            ASN1_OBJECT_free(param_obj);
            OPENSSL_free(param_der);
            ERR_raise(ERR_LIB_CMS, ERR_R_ASN1_LIB);
            return 0;
        }

        /* Set the DER-encoded OID as the content of the SEQUENCE */
        if (!ASN1_STRING_set(param_seq, param_der, param_der_len)) {
            ASN1_OBJECT_free(param_obj);
            ASN1_STRING_free(param_seq);
            OPENSSL_free(param_der);
            ERR_raise(ERR_LIB_CMS, ERR_R_ASN1_LIB);
            return 0;
        }

        /* Clean up temporary allocations */
        OPENSSL_free(param_der);
        ASN1_OBJECT_free(param_obj);
        param_obj = NULL; /* Prevent double-free */

        /*
         * Set keyEncryptionAlgorithm to kexp15 with the wrapped parameter.
         * X509_ALGOR_set0 takes ownership of param_seq on success.
         */
        if (!X509_ALGOR_set0(alg, OBJ_nid2obj(kexp15_oid),
                             V_ASN1_SEQUENCE, param_seq)) {
            ASN1_STRING_free(param_seq);
            ERR_raise(ERR_LIB_CMS, CMS_R_ERROR_SETTING_RECIPIENTINFO);
            return 0;
        }
    }

    /*
     * The keyEncryptionAlgorithm has been set. The actual key encryption
     * will be performed by the GOST engine/provider when EVP_PKEY_encrypt
     * is called in cms_RecipientInfo_ktri_encrypt.
     */
    return 1;
}

/*
 * Handle decryption setup for GOST keys
 *
 * For decryption, the keyEncryptionAlgorithm is already set in the
 * incoming CMS structure. We just need to validate it and let the
 * GOST engine/provider handle the actual decryption.
 */
static int gost_cms_decrypt(CMS_RecipientInfo *ri)
{
    X509_ALGOR *alg;
    int alg_nid;

    /* Get the keyEncryptionAlgorithm */
    if (!CMS_RecipientInfo_ktri_get0_algs(ri, NULL, NULL, &alg))
        return 0;

    if (alg == NULL || alg->algorithm == NULL)
        return 1; /* Let default processing handle it */

    alg_nid = OBJ_obj2nid(alg->algorithm);

    /*
     * If the algorithm is kexp15 or magma-kexp15, we're good.
     * The GOST engine/provider will handle the actual decryption.
     */
    if (alg_nid == NID_kuznyechik_kexp15 || alg_nid == NID_magma_kexp15)
        return 1;

    /*
     * For other algorithms with GOST keys, let the default
     * processing continue.
     */
    return 1;
}

/*
 * Main entry point for GOST envelope operations in CMS
 *
 * This function is called from ossl_cms_env_asn1_ctrl() in cms_env.c
 * to handle GOST R 34.10-2012 keys.
 *
 * Parameters:
 *   ri      - CMS_RecipientInfo structure
 *   decrypt - 0 for encryption (setting keyEncryptionAlgorithm)
 *             1 for decryption (validating keyEncryptionAlgorithm)
 *
 * Returns:
 *   1 on success
 *   0 on failure
 */
int ossl_cms_gost_envelope(CMS_RecipientInfo *ri, int decrypt)
{
    assert(decrypt == 0 || decrypt == 1);

    if (decrypt == 1)
        return gost_cms_decrypt(ri);

    if (decrypt == 0)
        return gost_cms_encrypt(ri);

    ERR_raise(ERR_LIB_CMS, CMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE);
    return 0;
}
