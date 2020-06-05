#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <array>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <string.h>
#include "sha1.h"

using namespace std;

#define IMAGE_DOS_SIGNATURE             0x5a4d // "MZ"
#define IMAGE_NT_SIGNATURE              0x00004550 // "PE\0\0"

#define IMAGE_DIRECTORY_ENTRY_CERTIFICATE     4

typedef struct {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY;

typedef struct {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
} IMAGE_OPTIONAL_HEADER32;

typedef struct {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader32;
} IMAGE_NT_HEADERS;

typedef struct {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

void hash_file(const string& fn) {
    IMAGE_DOS_HEADER dos_header;
    IMAGE_NT_HEADERS nt_headers;
    vector<IMAGE_SECTION_HEADER> sects;
    SHA1_CTX ctx;
    array<uint8_t, 20> hash;

    ifstream f(fn);

    SHA1Init(&ctx);

    f.read((char*)&dos_header, sizeof(IMAGE_DOS_HEADER));

    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE)
        throw runtime_error("Incorrect DOS signature.");

    SHA1Update(&ctx, &dos_header, sizeof(IMAGE_DOS_HEADER));

    {
        string stub;

        stub.resize(dos_header.e_lfanew - sizeof(IMAGE_DOS_HEADER));

        f.read((char*)stub.data(), stub.size());
        SHA1Update(&ctx, stub.data(), (uint32_t)stub.size());
    }

    f.read((char*)&nt_headers, sizeof(IMAGE_NT_HEADERS));

    if (nt_headers.Signature != IMAGE_NT_SIGNATURE)
        throw runtime_error("Incorrect PE signature.");

    SHA1Update(&ctx, &nt_headers, offsetof(IMAGE_NT_HEADERS, OptionalHeader32.CheckSum));
    SHA1Update(&ctx, &nt_headers.OptionalHeader32.Subsystem, sizeof(IMAGE_NT_HEADERS) - offsetof(IMAGE_NT_HEADERS, OptionalHeader32.Subsystem));

    for (unsigned int i = 0; i < nt_headers.OptionalHeader32.NumberOfRvaAndSizes; i++) {
        IMAGE_DATA_DIRECTORY dd;

        f.read((char*)&dd, sizeof(IMAGE_DATA_DIRECTORY));

        if (i != IMAGE_DIRECTORY_ENTRY_CERTIFICATE)
            SHA1Update(&ctx, &dd, sizeof(IMAGE_DATA_DIRECTORY));
    }

    sects.reserve(nt_headers.FileHeader.NumberOfSections);

    for (unsigned int i = 0; i < nt_headers.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sect;

        f.read((char*)&sect, sizeof(IMAGE_SECTION_HEADER));

        SHA1Update(&ctx, &sect, sizeof(IMAGE_SECTION_HEADER));

        sects.push_back(sect);
    }

    {
        string left;

        left.resize(nt_headers.OptionalHeader32.SizeOfHeaders - (uint32_t)f.tellg());

        f.read((char*)left.data(), left.size());
        SHA1Update(&ctx, left.data(), left.size());
    }

    sort(sects.begin(), sects.end(), [](const IMAGE_SECTION_HEADER& sect1, const IMAGE_SECTION_HEADER& sect2) {
        return sect1.PointerToRawData < sect2.PointerToRawData;
    });

    for (const auto& sect : sects) {
        if (sect.SizeOfRawData != 0) {
            string data;

            data.resize(sect.SizeOfRawData);
            f.seekg(sect.PointerToRawData);
            f.read((char*)data.data(), data.size());

            SHA1Update(&ctx, data.data(), data.size());
        }
    }

    SHA1Final(hash.data(), &ctx);

    printf("hash: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
           hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
           hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15],
           hash[16], hash[17], hash[18], hash[19]);
}

class x509_cert {
public:
    x509_cert(const string& fn) {
        FILE* f;

        f = fopen(fn.c_str(), "r");
        if (!f)
            throw runtime_error("Could not open certificate.");

        cert = PEM_read_X509(f, nullptr, nullptr, nullptr);
        if (!cert) {
            fclose(f);
            throw runtime_error("PEM_read_X509 failed");
        }

        fclose(f);
    }

    ~x509_cert() {
        X509_free(cert);
    }

    operator X509*() {
        return cert;
    }

private:
    X509* cert;
};

class evp_pkey {
public:
    evp_pkey(const string& fn) {
        FILE* f;

        f = fopen(fn.c_str(), "r");
        if (!f)
            throw runtime_error("Could not open certificate.");

        pkey = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
        if (!pkey) {
            fclose(f);
            throw runtime_error("PEM_read_PrivateKey failed");
        }

        fclose(f);
    }

    ~evp_pkey() {
        EVP_PKEY_free(pkey);
    }

    operator EVP_PKEY*() {
        return pkey;
    }

private:
    EVP_PKEY* pkey;
};

class pkcs7 {
public:
    pkcs7() {
        p7 = PKCS7_new();
    }

    ~pkcs7() {
        PKCS7_free(p7);
    }

    operator PKCS7*() {
        return p7;
    }

private:
    PKCS7* p7;
};

class openssl_error : public exception {
public:
    openssl_error(const string& func) {
        unsigned long err;
        char buf[256];

        err = ERR_get_error();
        ERR_error_string(err, buf);

        msg = func + " failed: " + buf;
    }

    const char* what() const noexcept {
        return msg.c_str();
    }

private:
    string msg;
};

static int PKCS7_type_is_other(PKCS7* p7) {
   switch (OBJ_obj2nid(p7->type)) {
    case NID_pkcs7_data:
    case NID_pkcs7_signed:
    case NID_pkcs7_enveloped:
    case NID_pkcs7_signedAndEnveloped:
    case NID_pkcs7_digest:
    case NID_pkcs7_encrypted:
        return 0;

    default:
        return 1;
   }
}

static int PKCS7_bio_add_digest(BIO **pbio, X509_ALGOR *alg)
{
    BIO *btmp;
    const EVP_MD *md;
    if ((btmp=BIO_new(BIO_f_md())) == NULL)
    {
        PKCS7err(PKCS7_F_PKCS7_BIO_ADD_DIGEST,ERR_R_BIO_LIB);
        goto err;
    }

    md=EVP_get_digestbyobj(alg->algorithm);
    if (md == NULL)
    {
        PKCS7err(PKCS7_F_PKCS7_BIO_ADD_DIGEST,PKCS7_R_UNKNOWN_DIGEST_TYPE);
        goto err;
    }

    BIO_set_md(btmp,md);
    if (*pbio == NULL)
        *pbio=btmp;
    else if (!BIO_push(*pbio,btmp))
    {
        PKCS7err(PKCS7_F_PKCS7_BIO_ADD_DIGEST,ERR_R_BIO_LIB);
        goto err;
    }
    btmp=NULL;

    return 1;

    err:
    if (btmp)
        BIO_free(btmp);
    return 0;

}

static int pkcs7_encode_rinfo(PKCS7_RECIP_INFO *ri,
                              unsigned char *key, int keylen)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *ek = NULL;
    int ret = 0;
    size_t eklen;

    pkey = X509_get_pubkey(ri->cert);

    if (!pkey)
        return 0;

    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx)
        return 0;

    if (EVP_PKEY_encrypt_init(pctx) <= 0)
        goto err;

    if (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_ENCRYPT,
        EVP_PKEY_CTRL_PKCS7_ENCRYPT, 0, ri) <= 0)
    {
        PKCS7err(PKCS7_F_PKCS7_ENCODE_RINFO, PKCS7_R_CTRL_ERROR);
        goto err;
    }

    if (EVP_PKEY_encrypt(pctx, NULL, &eklen, key, keylen) <= 0)
        goto err;

    ek = (unsigned char*)OPENSSL_malloc(eklen);

    if (ek == NULL)
    {
        PKCS7err(PKCS7_F_PKCS7_ENCODE_RINFO, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EVP_PKEY_encrypt(pctx, ek, &eklen, key, keylen) <= 0)
        goto err;

    ASN1_STRING_set0(ri->enc_key, ek, (int)eklen);
    ek = NULL;

    ret = 1;

    err:
    if (pkey)
        EVP_PKEY_free(pkey);
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    if (ek)
        OPENSSL_free(ek);
    return ret;
}

static ASN1_STRING* PKCS7_get_sequence(PKCS7 *p7) {
    if (PKCS7_type_is_other(p7) && p7->d.other
        && (p7->d.other->type == V_ASN1_SEQUENCE))
        return p7->d.other->value.sequence;

    return NULL;
}

static BIO* pkcs_data_init(PKCS7 *p7, BIO *bio) {
    int i;
    BIO *out=NULL,*btmp=NULL;
    X509_ALGOR *xa = NULL;
    const EVP_CIPHER *evp_cipher=NULL;
    STACK_OF(X509_ALGOR) *md_sk=NULL;
    STACK_OF(PKCS7_RECIP_INFO) *rsk=NULL;
    X509_ALGOR *xalg=NULL;
    PKCS7_RECIP_INFO *ri=NULL;
//     ASN1_OCTET_STRING *os=NULL;
    ASN1_STRING *seq = NULL;

    i=OBJ_obj2nid(p7->type);
    p7->state=PKCS7_S_HEADER;

    md_sk=p7->d.sign->md_algs;
//     os = PKCS7_get_octet_string(p7->d.sign->contents);
    seq = PKCS7_get_sequence(p7->d.sign->contents);

    for (i=0; i<sk_X509_ALGOR_num(md_sk); i++) {
        if (!PKCS7_bio_add_digest(&out, sk_X509_ALGOR_value(md_sk, i)))
            goto err;
    }

    if (xa && !PKCS7_bio_add_digest(&out, xa))
        goto err;

    if (evp_cipher != NULL)
    {
        unsigned char key[EVP_MAX_KEY_LENGTH];
        unsigned char iv[EVP_MAX_IV_LENGTH];
        int keylen,ivlen;
        EVP_CIPHER_CTX *ctx;

        if ((btmp=BIO_new(BIO_f_cipher())) == NULL)
        {
            PKCS7err(PKCS7_F_PKCS7_DATAINIT,ERR_R_BIO_LIB);
            goto err;
        }
        BIO_get_cipher_ctx(btmp, &ctx);
        keylen=EVP_CIPHER_key_length(evp_cipher);
        ivlen=EVP_CIPHER_iv_length(evp_cipher);
        xalg->algorithm = OBJ_nid2obj(EVP_CIPHER_type(evp_cipher));
        if (ivlen > 0) {
            if (RAND_bytes(iv, ivlen) <= 0)
                goto err;
        }
        if (EVP_CipherInit_ex(ctx, evp_cipher, NULL, NULL, NULL, 1)<=0)
            goto err;
        if (EVP_CIPHER_CTX_rand_key(ctx, key) <= 0)
            goto err;
        if (EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, 1) <= 0)
            goto err;

        if (ivlen > 0) {
            if (xalg->parameter == NULL) {
                xalg->parameter = ASN1_TYPE_new();
                if (xalg->parameter == NULL)
                    goto err;
            }
            if(EVP_CIPHER_param_to_asn1(ctx, xalg->parameter) < 0)
                goto err;
        }

        /* Lets do the pub key stuff :-) */
        for (i=0; i<sk_PKCS7_RECIP_INFO_num(rsk); i++)
        {
            ri=sk_PKCS7_RECIP_INFO_value(rsk,i);
            if (pkcs7_encode_rinfo(ri, key, keylen) <= 0)
                goto err;
        }
        OPENSSL_cleanse(key, keylen);

        if (out == NULL)
            out=btmp;
        else
            BIO_push(out,btmp);
        btmp=NULL;
    }

    if (bio == NULL)
    {
        if (seq) {
            long len;
            int tag, xclass;
            const unsigned char *p = seq->data;

            /* Skip past the SEQUENCE header */

            ASN1_get_object(&p, &len, &tag, &xclass, seq->length);

            bio = BIO_new_mem_buf(p, (int)len);
        }

        if(bio == NULL)
        {
            bio=BIO_new(BIO_s_mem());
            if (bio == NULL)
                goto err;
            BIO_set_mem_eof_return(bio,0);
        }
    }
    if (out)
        BIO_push(out,bio);
    else
        out = bio;
    bio=NULL;
    if (0)
    {
        err:
        if (out != NULL)
            BIO_free_all(out);
        if (btmp != NULL)
            BIO_free_all(btmp);
        out=NULL;
    }
    return(out);
}

static BIO *PKCS7_find_digest(EVP_MD_CTX **pmd, BIO *bio, int nid)
{
    for (;;) {
        bio = BIO_find_type(bio, BIO_TYPE_MD);
        if (bio == NULL) {
            PKCS7err(PKCS7_F_PKCS7_FIND_DIGEST,
                     PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST);
            return NULL;
        }
        BIO_get_md_ctx(bio, pmd);
        if (*pmd == NULL) {
            PKCS7err(PKCS7_F_PKCS7_FIND_DIGEST, ERR_R_INTERNAL_ERROR);
            return NULL;
        }
        if (EVP_MD_CTX_type(*pmd) == nid)
            return bio;
        bio = BIO_next(bio);
    }
    return NULL;
}

static int do_pkcs7_signed_attrib(PKCS7_SIGNER_INFO *si, EVP_MD_CTX *mctx)
{
    unsigned char md_data[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    /* Add signing time if not already present */
    if (!PKCS7_get_signed_attribute(si, NID_pkcs9_signingTime)) {
        if (!PKCS7_add0_attrib_signing_time(si, NULL)) {
            PKCS7err(PKCS7_F_DO_PKCS7_SIGNED_ATTRIB, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }

    /* Add digest */
    if (!EVP_DigestFinal_ex(mctx, md_data, &md_len)) {
        PKCS7err(PKCS7_F_DO_PKCS7_SIGNED_ATTRIB, ERR_R_EVP_LIB);
        return 0;
    }
    if (!PKCS7_add1_attrib_digest(si, md_data, md_len)) {
        PKCS7err(PKCS7_F_DO_PKCS7_SIGNED_ATTRIB, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    /* Now sign the attributes */
    if (!PKCS7_SIGNER_INFO_sign(si))
        return 0;

    return 1;
}

static int pkcs_data_final(PKCS7 *p7, BIO *bio)
{
    int ret = 0;
    int i, j;
    BIO *btmp;
    PKCS7_SIGNER_INFO *si;
    EVP_MD_CTX *mdc, *ctx_tmp;
    STACK_OF(X509_ATTRIBUTE) *sk;
    STACK_OF(PKCS7_SIGNER_INFO) *si_sk = NULL;
//     ASN1_OCTET_STRING *os = NULL;
    ASN1_STRING *seq = NULL;

    if (p7 == NULL) {
        PKCS7err(PKCS7_F_PKCS7_DATAFINAL, PKCS7_R_INVALID_NULL_POINTER);
        return 0;
    }

    if (p7->d.ptr == NULL) {
        PKCS7err(PKCS7_F_PKCS7_DATAFINAL, PKCS7_R_NO_CONTENT);
        return 0;
    }

    ctx_tmp = EVP_MD_CTX_new();
    if (ctx_tmp == NULL) {
        PKCS7err(PKCS7_F_PKCS7_DATAFINAL, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    i = OBJ_obj2nid(p7->type);
    p7->state = PKCS7_S_HEADER;

    si_sk = p7->d.sign->signer_info;
//     os = PKCS7_get_octet_string(p7->d.sign->contents);
    seq = PKCS7_get_sequence(p7->d.sign->contents);

    for (i = 0; i < sk_PKCS7_SIGNER_INFO_num(si_sk); i++) {
        si = sk_PKCS7_SIGNER_INFO_value(si_sk, i);
        if (si->pkey == NULL)
            continue;

        j = OBJ_obj2nid(si->digest_alg->algorithm);

        btmp = bio;

        btmp = PKCS7_find_digest(&mdc, btmp, j);

        if (btmp == NULL)
            goto err;

        /*
            * We now have the EVP_MD_CTX, lets do the signing.
            */
        if (!EVP_MD_CTX_copy_ex(ctx_tmp, mdc))
            goto err;

        sk = si->auth_attr;

        /*
            * If there are attributes, we add the digest attribute and only
            * sign the attributes
            */
        if (sk_X509_ATTRIBUTE_num(sk) > 0) {
            if (!do_pkcs7_signed_attrib(si, ctx_tmp))
                goto err;
        } else {
            unsigned char *abuf = NULL;
            unsigned int abuflen;
            abuflen = EVP_PKEY_size(si->pkey);
            abuf = (unsigned char*)OPENSSL_malloc(abuflen);
            if (abuf == NULL)
                goto err;

            if (!EVP_SignFinal(ctx_tmp, abuf, &abuflen, si->pkey)) {
                OPENSSL_free(abuf);
                PKCS7err(PKCS7_F_PKCS7_DATAFINAL, ERR_R_EVP_LIB);
                goto err;
            }
            ASN1_STRING_set0(si->enc_digest, abuf, abuflen);
        }
    }

    /*
        * NOTE(emilia): I think we only reach os == NULL here because detached
        * digested data support is broken.
        */
    if (!seq)
        goto err;
//     if (!(os->flags & ASN1_STRING_FLAG_NDEF)) {
//         char *cont;
//         long contlen;
//         btmp = BIO_find_type(bio, BIO_TYPE_MEM);
//         if (btmp == NULL) {
//             PKCS7err(PKCS7_F_PKCS7_DATAFINAL, PKCS7_R_UNABLE_TO_FIND_MEM_BIO);
//             goto err;
//         }
//         contlen = BIO_get_mem_data(btmp, &cont);
//         /*
//             * Mark the BIO read only then we can use its copy of the data
//             * instead of making an extra copy.
//             */
//         BIO_set_flags(btmp, BIO_FLAGS_MEM_RDONLY);
//         BIO_set_mem_eof_return(btmp, 0);
//         ASN1_STRING_set0(os, (unsigned char *)cont, (int)contlen);
//     }

    ret = 1;
err:
    EVP_MD_CTX_free(ctx_tmp);
    return ret;
}

void test_sign() {
    int content_nid;

    content_nid = OBJ_create("1.3.6.1.4.1.311.2.1.4", "spcIndirectDataContext", "spcIndirectDataContext");

    if (content_nid == NID_undef)
        throw openssl_error("OBJ_create");

    x509_cert cert("/home/hellas/wine/fs/inftool/certificate.crt");

    evp_pkey priv_key("/home/hellas/wine/fs/inftool/privateKey.key");

    // FIXME - form spcIndirectDataContext
    // FIXME - use SHA1 rather than SHA256

    BIO* mem = BIO_new(BIO_s_mem());
    BIO_puts(mem, "hello");

    pkcs7 p7;

    if (!PKCS7_set_type(p7, NID_pkcs7_signed))
        throw openssl_error("PKCS7_set_type");

    {
        PKCS7* content = PKCS7_new();

        ASN1_TYPE* asn1 = ASN1_TYPE_new();

        ASN1_STRING* str = ASN1_STRING_new();
        ASN1_STRING_set(str, "\x30\x21\x30\x09\x06\x05\x2B\x0E\x03\x02\x1A\x05\x00\x04\x14\xEC\x41\xB3\xAE\xBD\x64\xD2\xA2\x42\x46\x66\x81\xD9\xA6\x14\x09\x00\x7C\x1B\xF0", 35); // FIXME

        ASN1_TYPE_set(asn1, V_ASN1_SEQUENCE, str);

        if (!PKCS7_set0_type_other(content, content_nid, asn1))
            throw openssl_error("PKCS7_set0_type_other");

        if (!PKCS7_set_content(p7, content))
            throw openssl_error("PKCS7_set_content");
    }

    if (!PKCS7_sign_add_signer(p7, cert, priv_key, nullptr, 0))
        throw openssl_error("PKCS7_sign_add_signer");

    BIO* p7bio = pkcs_data_init(p7, nullptr);

    if (!p7bio)
        throw openssl_error("PKCS7_dataInit");

    SMIME_crlf_copy(mem, p7bio, 0);

    BIO_flush(p7bio);

    if (!pkcs_data_final(p7, p7bio))
        throw openssl_error("pkcs_data_final");

    if (!i2d_PKCS7_fp(stdout, p7))
        throw openssl_error("i2d_PKCS7_fp");

    // FIXME - embed in PE file
}
