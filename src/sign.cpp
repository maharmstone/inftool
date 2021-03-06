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

static void pkcs_data_final(PKCS7* p7, ASN1_STRING* seq) {
    PKCS7_SIGNER_INFO* si;
    STACK_OF(PKCS7_SIGNER_INFO)* si_sk;

    if (!p7->d.ptr)
        throw runtime_error("p7->d.ptr was NULL");

    p7->state = PKCS7_S_HEADER;

    si_sk = p7->d.sign->signer_info;

    for (int i = 0; i < sk_PKCS7_SIGNER_INFO_num(si_sk); i++) {
        si = sk_PKCS7_SIGNER_INFO_value(si_sk, i);
        if (!si->pkey)
            continue;

//         int j = OBJ_obj2nid(si->digest_alg->algorithm);

        // FIXME - attrib spcSpOpusInfo
        // FIXME - attrib contentType (set to spcIndirectDataContext)
        // FIXME - attrib spcStatementType

        long len;
        int tag, xclass;
        const unsigned char *p = seq->data;

        /* Skip past the SEQUENCE header */

        ASN1_get_object(&p, &len, &tag, &xclass, seq->length);

        unsigned char md_data[EVP_MAX_MD_SIZE];
        unsigned int md_len = 32; // FIXME

        SHA256(p, len, md_data); // FIXME - use specified algorithm

        if (!PKCS7_add1_attrib_digest(si, md_data, md_len))
            throw runtime_error("PKCS7_add1_attrib_digest failed");

        /* Now sign the attributes */
        if (!PKCS7_SIGNER_INFO_sign(si))
            throw openssl_error("PKCS7_SIGNER_INFO_sign");
    }
}

void test_sign() {
    int content_nid;

    content_nid = OBJ_create("1.3.6.1.4.1.311.2.1.4", "spcIndirectDataContext", "spcIndirectDataContext");

    if (content_nid == NID_undef)
        throw openssl_error("OBJ_create");

    x509_cert cert("/home/hellas/wine/fs/inftool/certificate.crt");

    evp_pkey priv_key("/home/hellas/wine/fs/inftool/privateKey.key");

    // FIXME - use SHA1 rather than SHA256

    pkcs7 p7;

    if (!PKCS7_set_type(p7, NID_pkcs7_signed))
        throw openssl_error("PKCS7_set_type");

    // FIXME - form spcIndirectDataContext
    ASN1_STRING* str = ASN1_STRING_new();
    ASN1_STRING_set(str, "\x30\x21\x30\x09\x06\x05\x2B\x0E\x03\x02\x1A\x05\x00\x04\x14\xEC\x41\xB3\xAE\xBD\x64\xD2\xA2\x42\x46\x66\x81\xD9\xA6\x14\x09\x00\x7C\x1B\xF0", 35); // FIXME

    {
        PKCS7* content = PKCS7_new();

        ASN1_TYPE* asn1 = ASN1_TYPE_new();

        ASN1_TYPE_set(asn1, V_ASN1_SEQUENCE, str);

        if (!PKCS7_set0_type_other(content, content_nid, asn1))
            throw openssl_error("PKCS7_set0_type_other");

        if (!PKCS7_set_content(p7, content))
            throw openssl_error("PKCS7_set_content");
    }

    if (!PKCS7_sign_add_signer(p7, cert, priv_key, nullptr, 0))
        throw openssl_error("PKCS7_sign_add_signer");

    pkcs_data_final(p7, str);

    if (!i2d_PKCS7_fp(stdout, p7))
        throw openssl_error("i2d_PKCS7_fp");

    // FIXME - embed in PE file
}
