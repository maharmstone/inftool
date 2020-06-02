#include "asn.h"
#include <sstream>
#include <array>

using namespace std;

static const obj_id pkcs7_rsa{1, 2, 840, 113549, 1, 7, 2};
static const obj_id obj_id_sha1{1, 3, 14, 3, 2, 26};

static const obj_id ms_cert_trust_list{1, 3, 6, 1, 4, 1, 311, 10, 1};
static const obj_id ms_catalogue_list{1, 3, 6, 1, 4, 1, 311, 12, 1, 1};
static const obj_id ms_catalogue_list_member{1, 3, 6, 1, 4, 1, 311, 12, 1, 2};
static const obj_id ms_catalogue_name_value{1, 3, 6, 1, 4, 1, 311, 12, 2, 1};
static const obj_id ms_catalogue_member_info{1, 3, 6, 1, 4, 1, 311, 12, 2, 2};
static const obj_id ms_indirect_data_context{1, 3, 6, 1, 4, 1, 311, 2, 1, 4};
static const obj_id ms_spc_pe_image_data{1, 3, 6, 1, 4, 1, 311, 2, 1, 15};

static unsigned int der_int_length(int64_t v) {
    if (v >= 0) {
        if (v < 0x80)
            return 1;
        else if (v < 0x8000)
            return 2;
        else if (v < 0x800000)
            return 3;
        else if (v < 0x80000000)
            return 4;
        else if (v < 0x8000000000)
            return 5;
        else if (v < 0x800000000000)
            return 6;
        else if (v < 0x80000000000000)
            return 7;
        else
            return 8;
    } else {
        if (v >= -0x80)
            return 1;
        else if (v >= -0x8000)
            return 2;
        else if (v >= -0x800000)
            return 3;
        else if (v >= -0x80000000)
            return 4;
        else if (v >= -0x8000000000)
            return 5;
        else if (v >= -0x800000000000)
            return 6;
        else if (v >= -0x80000000000000)
            return 7;
        else
            return 8;
    }
}

static unsigned int der_length_length(uint64_t v) {
    if (v < 0x80)
        return 1;
    else if (v < 0x8000)
        return 3;
    else if (v < 0x800000)
        return 4;
    else if (v < 0x80000000)
        return 5;
    else if (v < 0x8000000000)
        return 6;
    else if (v < 0x800000000000)
        return 7;
    else if (v < 0x80000000000000)
        return 8;
    else
        return 9;
}

static void der_write_int(ostream& out, int64_t v) {
    if (v >= 0) {
        uint64_t c = __builtin_bswap64((uint64_t)v);

        if (v < 0x80)
            out.write((const char*)&c + 7, 1);
        else if (v < 0x8000)
            out.write((const char*)&c + 6, 2);
        else if (v < 0x800000)
            out.write((const char*)&c + 5, 3);
        else if (v < 0x80000000)
            out.write((const char*)&c + 4, 4);
        else if (v < 0x8000000000)
            out.write((const char*)&c + 3, 5);
        else if (v < 0x800000000000)
            out.write((const char*)&c + 2, 6);
        else if (v < 0x80000000000000)
            out.write((const char*)&c + 1, 7);
        else
            out.write((const char*)&c, 8);
    } else {
        uint64_t c = __builtin_bswap64(v);

        if (v >= -0x80)
            out.write((const char*)&c + 7, 1);
        else if (v >= -0x8000)
            out.write((const char*)&c + 6, 2);
        else if (v >= -0x800000)
            out.write((const char*)&c + 5, 3);
        else if (v >= -0x80000000)
            out.write((const char*)&c + 4, 4);
        else if (v >= -0x8000000000)
            out.write((const char*)&c + 3, 5);
        else if (v >= -0x800000000000)
            out.write((const char*)&c + 2, 6);
        else if (v >= -0x80000000000000)
            out.write((const char*)&c + 1, 7);
        else
            out.write((const char*)&c, 8);
    }
}

static void der_write_length(ostream& out, uint64_t v) {
    uint64_t c;
    uint8_t c2;

    if (v < 0x80) {
        c2 = (uint8_t)v;
        out.write((char*)&c2, 1);
        return;
    }

    c = __builtin_bswap64((uint64_t)v);

    if (v < 0x80) {
        c2 = 0x81;
        out.write((char*)&c2, 1);
        out.write((const char*)&c + 7, 1);
    } else if (v < 0x8000) {
        c2 = 0x82;
        out.write((char*)&c2, 1);
        out.write((const char*)&c + 6, 2);
    } else if (v < 0x800000) {
        c2 = 0x83;
        out.write((char*)&c2, 1);
        out.write((const char*)&c + 5, 3);
    } else if (v < 0x80000000) {
        c2 = 0x84;
        out.write((char*)&c2, 1);
        out.write((const char*)&c + 4, 4);
    } else if (v < 0x8000000000) {
        c2 = 0x85;
        out.write((char*)&c2, 1);
        out.write((const char*)&c + 3, 5);
    } else if (v < 0x800000000000) {
        c2 = 0x86;
        out.write((char*)&c2, 1);
        out.write((const char*)&c + 2, 6);
    } else if (v < 0x80000000000000) {
        c2 = 0x87;
        out.write((char*)&c2, 1);
        out.write((const char*)&c + 1, 7);
    } else {
        c2 = 0x88;
        out.write((char*)&c2, 1);
        out.write((const char*)&c, 8);
    }
}

void der::dump(ostream& out) const {
    switch (type) {
        case der_type::sequence: {
            unsigned int len = length();
            char c = DER_SEQUENCE;

            out.write(&c, sizeof(unsigned char));
            der_write_length(out, len);

            for (const auto& v : get<vector<der>>(value)) {
                v.dump(out);
            }

            break;
        }

        case der_type::integer: {
            char c = DER_INTEGER;

            out.write(&c, sizeof(unsigned char));
            der_write_length(out, length());
            der_write_int(out, get<int64_t>(value));

            break;
        }

        case der_type::ia5string: {
            char c = DER_IA5STRING;

            out.write(&c, sizeof(unsigned char));
            der_write_length(out, length());
            out.write(get<string>(value).data(), get<string>(value).length());

            break;
        }

        case der_type::obj_id: {
            uint8_t c = DER_OBJ_ID;
            const auto& obj = get<obj_id>(value);

            out.write((const char*)&c, sizeof(unsigned char));
            der_write_length(out, length());

            c = (uint8_t)((obj.nums[0] * 40) + obj.nums[1]);
            out.write((const char*)&c, sizeof(unsigned char));

            for (unsigned int i = 2; i < obj.nums.size(); i++) {
                auto n = obj.nums[i];

                if (n < 0x80) {
                    auto v = (uint8_t)n;

                    out.write((const char*)&v, sizeof(unsigned char));
                } else if (n < 0x4000) {
                    uint16_t v;

                    v = (uint16_t)(0x8000 | ((n & 0x3f80) << 1) | (n & 0x7f));
                    v = __builtin_bswap16(v);

                    out.write((const char*)&v, sizeof(uint16_t));
                } else if (n < 0x200000) {
                    uint32_t v;

                    v = 0x808000 | ((n & 0x1fc000) << 2) | ((n & 0x3f80) << 1) | (n & 0x7f);
                    v = __builtin_bswap32(v);

                    out.write((const char*)&v + 1, 3);
                } else
                    throw runtime_error("Value out of range.");
            }

            break;
        }

        case der_type::context_specific: {
            unsigned int len = length();
            uint8_t c = DER_CONTEXT_SPECIFIC;

            out.write((char*)&c, sizeof(unsigned char));
            der_write_length(out, len);

            for (const auto& v : get<context_specific>(value).els) {
                v.dump(out);
            }

            break;
        }

        case der_type::set: {
            unsigned int len = length();
            uint8_t c = DER_SET;

            out.write((char*)&c, sizeof(unsigned char));
            der_write_length(out, len);

            for (const auto& v : get<der_set>(value).els) {
                v.dump(out);
            }

            break;
        }

        case der_type::null: {
            unsigned int len = length();
            uint8_t c = DER_NULL;

            out.write((char*)&c, sizeof(unsigned char));
            der_write_length(out, len);

            break;
        }

        case der_type::octet_string: {
            char c = DER_OCTET_STRING;

            out.write(&c, sizeof(unsigned char));
            der_write_length(out, length());
            out.write(get<string>(value).data(), get<string>(value).length());

            break;
        }

        case der_type::utc_time: {
            char c = DER_UTCTIME;
            auto t = chrono::system_clock::to_time_t(get<chrono::system_clock::time_point>(value));
            struct tm tm;
            char s[14];

            gmtime_r(&t, &tm);

            sprintf(s, "%02u%02u%02u%02u%02u%02uZ", tm.tm_year % 100, tm.tm_mon + 1, tm.tm_mday,
                    tm.tm_hour, tm.tm_min, tm.tm_sec);

            out.write(&c, sizeof(unsigned char));
            der_write_length(out, length());
            out.write(s, sizeof(s) - 1);

            break;
        }

        case der_type::bmp_string: {
            char c = DER_BMPSTRING;
            const auto& us = get<u16string>(value);

            out.write(&c, sizeof(unsigned char));
            der_write_length(out, length());

            for (const auto& c : us) {
                char16_t v = __builtin_bswap16(c);

                out.write((char*)&v, sizeof(char16_t));
            }

            break;
        }

        case der_type::bit_string: {
            uint8_t c = DER_BIT_STRING;
            const auto& bs = get<bit_string>(value);
            uint64_t v;

            out.write((char*)&c, sizeof(unsigned char));
            der_write_length(out, length());

            c = 8 - (bs.bits % 8);

            if (c == 8)
                c = 0;

            out.write((char*)&c, sizeof(unsigned char));

            v = __builtin_bswap64(bs.value << c);

            if (bs.bits <= 8)
                out.write((char*)&v + 7, 1);
            else if (bs.bits <= 16)
                out.write((char*)&v + 6, 2);
            else if (bs.bits <= 24)
                out.write((char*)&v + 5, 3);
            else if (bs.bits <= 32)
                out.write((char*)&v + 4, 4);
            else if (bs.bits <= 40)
                out.write((char*)&v + 3, 5);
            else if (bs.bits <= 48)
                out.write((char*)&v + 2, 6);
            else if (bs.bits <= 56)
                out.write((char*)&v + 1, 7);
            else
                out.write((char*)&v, 8);
        }
    }
}

unsigned int der::length() const {
    switch (type) {
        case der_type::sequence: {
            unsigned int len = 0;

            for (const auto& v : get<vector<der>>(value)) {
                unsigned int item_len = v.length();

                len++;
                len += der_length_length(item_len);
                len += v.length();
            }

            return len;
        }

        case der_type::integer:
            return der_int_length(get<int64_t>(value));

        case der_type::ia5string:
        case der_type::octet_string:
            return (unsigned int)get<string>(value).length();

        case der_type::obj_id: {
            unsigned int len = 1;
            const auto& obj = get<obj_id>(value);

            for (unsigned int i = 2; i < obj.nums.size(); i++) {
                auto n = obj.nums[i];

                if (n < 0x80)
                    len++;
                else if (n < 0x4000)
                    len += 2;
                else if (n < 0x200000)
                    len += 3;
                else
                    throw runtime_error("Value out of range.");
            }

            return len;
        }

        case der_type::context_specific: {
            unsigned int len = 0;

            for (const auto& v : get<context_specific>(value).els) {
                unsigned int item_len = v.length();

                len++;
                len += der_length_length(item_len);
                len += v.length();
            }

            return len;
        }

        case der_type::set: {
            unsigned int len = 0;

            for (const auto& v : get<der_set>(value).els) {
                unsigned int item_len = v.length();

                len++;
                len += der_length_length(item_len);
                len += v.length();
            }

            return len;
        }

        case der_type::null:
            return 0;

        case der_type::utc_time:
            return 13;

        case der_type::bmp_string:
            return (unsigned int)(get<u16string>(value).length() * sizeof(char16_t));

        case der_type::bit_string: {
            const auto& bs = get<bit_string>(value);

            return ((bs.bits + 7) / 8) + 1;
        }
    }

    return 0;
}

static void add_kv_item(der& store, const u16string& key, const u16string& value, bool blob) {
    der seq{vector<der>{ms_catalogue_name_value}};
    der val{vector<der>{}};

    val.emplace(key);
    val.emplace(0x10010001);
    val.emplace(octet_string{value});

    if (blob) {
        stringstream ss;
        val.dump(ss);

        seq.emplace(octet_string{ss.str()});
    } else
        seq.emplace(der_set{val});

    store.emplace(seq);
}

static char16_t u16_digit(unsigned int num) {
    if (num < 10)
        return (char16_t)(num + u'0');
    else
        return (char16_t)(num - 10 + u'A');
}

static void add_file(der& seq, const u16string& fn, const u16string& os_attr, const span<uint8_t>& hash) {
    der set{der_set{}};
    u16string tag;

    tag.reserve(hash.size() * 2);
    for (const auto& h : hash) {
        tag += u16_digit(h >> 4);
        tag += u16_digit(h & 0xf);
    }

    add_kv_item(set, u"File", fn, false);

    set.emplace(
        vector<der>{
            ms_catalogue_member_info,
            der_set{
                vector<der>{
                    u"{C689AAB8-8E78-11D0-8C47-00C04FC295EE}"s,
                    512
                }
            }
        }
    );

    set.emplace(
        vector<der>{
            ms_indirect_data_context,
            der_set{
                vector<der>{
//                     vector<der>{
//                         ms_spc_pe_image_data,
//                         vector<der>{
//                             bit_string(3, 5)
//                         [0] (1 elem)
//                             [2] (1 elem)
//                                 [0] (28 byte) 003C003C003C004F00620073006F006C006500740065003E003E003E
//                         }
//                     },
                    vector<der>{
                        vector<der>{
                            obj_id_sha1,
                            nullptr
                        },
                        octet_string{hash}
                    }
                }
            }
        }
    );

    add_kv_item(set, u"OSAttr", os_attr, false);

    seq.emplace(vector<der>{octet_string{tag}, set});
}

static void main2() {
    der cert_trust_list{vector<der>{}};

    static const u16string os_attr = u"2:5.1,2:5.2,2:6.0,2:6.1,2:6.2,2:6.3,2:10.0";

    cert_trust_list.emplace(vector<der>{ms_catalogue_list});
    cert_trust_list.emplace(octet_string{"\x5E\x0B\x52\x27\xB8\x66\xB1\x44\xA4\x50\xDF\xAA\x15\x4B\x67\x1B"}); // FIXME - hash? ("list identifier")
    cert_trust_list.emplace(chrono::system_clock::now());

    cert_trust_list.emplace(vector<der>{ms_catalogue_list_member, nullptr});

    der files{vector<der>{}};

    array<uint8_t, 20> hash{ 0x12, 0x09, 0x8E, 0x4F, 0x37, 0x5C, 0xE6, 0x7D, 0x97, 0x36, 0xD2, 0x43, 0x43, 0x43, 0x1E, 0xE7, 0xBE, 0xFE, 0xC2, 0x3E };
    add_file(files, u"shellbtrfs.dll", os_attr, hash);

    cert_trust_list.emplace(files);

    der kv_store{vector<der>{}};

    add_kv_item(kv_store, u"OS", u"XPX86,XPX64,VistaX86,VistaX64,7X86,7X64,8X86,8X64,8ARM,_v63,_v63_X64,_v63_ARM,_v100,_v100_X64", true);
    add_kv_item(kv_store, u"HWID2", u"root\\btrfs", true);
    add_kv_item(kv_store, u"HWID1", u"btrfsvolume", true);

    cert_trust_list.emplace(context_specific{kv_store});

    der main_seq{vector<der>{}};

    main_seq.emplace(1);
    main_seq.emplace(der_set{});
    main_seq.emplace(vector<der>{ms_cert_trust_list, context_specific{cert_trust_list}});
    main_seq.emplace(der_set{});

    der main{vector<der>{pkcs7_rsa, context_specific{main_seq}}};

    main.dump(cout);
}

int main() {
    try {
        main2();
    } catch (const exception& e) {
        cerr << e.what() << endl;
    }
}
