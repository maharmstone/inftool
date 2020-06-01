#include "asn.h"

using namespace std;

static const obj_id pkcs7_rsa{1, 2, 840, 113549, 1, 7, 2};
static const obj_id ms_cert_trust_list{1, 3, 6, 1, 4, 1, 311, 10, 1};
static const obj_id ms_catalogue_list{1, 3, 6, 1, 4, 1, 311, 12, 1, 1};
static const obj_id ms_catalogue_list_member{1, 3, 6, 1, 4, 1, 311, 12, 1, 2};

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

void der::dump(ostream& out) const {
    switch (type) {
        case der_type::sequence: {
            unsigned int len = length();
            char c = DER_SEQUENCE;

            out.write(&c, sizeof(unsigned char));
            der_write_int(out, len);

            for (const auto& v : get<vector<der>>(value)) {
                v.dump(out);
            }

            break;
        }

        case der_type::integer: {
            char c = DER_INTEGER;

            out.write(&c, sizeof(unsigned char));
            der_write_int(out, length());
            der_write_int(out, get<int64_t>(value));

            break;
        }

        case der_type::ia5string: {
            char c = DER_IA5STRING;

            out.write(&c, sizeof(unsigned char));
            der_write_int(out, length());
            out.write(get<string>(value).data(), get<string>(value).length());

            break;
        }

        case der_type::obj_id: {
            uint8_t c = DER_OBJ_ID;
            const auto& obj = get<obj_id>(value);

            out.write((const char*)&c, sizeof(unsigned char));
            der_write_int(out, length());

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
            der_write_int(out, len);

            for (const auto& v : get<context_specific>(value).els) {
                v.dump(out);
            }

            break;
        }

        case der_type::set: {
            unsigned int len = length();
            uint8_t c = DER_SET;

            out.write((char*)&c, sizeof(unsigned char));
            der_write_int(out, len);

            for (const auto& v : get<der_set>(value).els) {
                v.dump(out);
            }

            break;
        }

        case der_type::null: {
            unsigned int len = length();
            uint8_t c = DER_NULL;

            out.write((char*)&c, sizeof(unsigned char));
            der_write_int(out, len);

            break;
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
                len += der_int_length(item_len);
                len += v.length();
            }

            return len;
        }

        case der_type::integer:
            return der_int_length(get<int64_t>(value));

        case der_type::ia5string:
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
                len += der_int_length(item_len);
                len += v.length();
            }

            return len;
        }

        case der_type::set: {
            unsigned int len = 0;

            for (const auto& v : get<der_set>(value).els) {
                unsigned int item_len = v.length();

                len++;
                len += der_int_length(item_len);
                len += v.length();
            }

            return len;
        }

        case der_type::null:
            return 0;
    }

    return 0;
}

static void main2() {
    der cert_trust_list{vector<der>{}};

    cert_trust_list.emplace(vector<der>{ms_catalogue_list});
//     OCTET STRING (16 byte) 5E0B5227B866B144A450DFAA154B671B // list identifier
//     UTCTime 2020-01-28 21:16:11 UTC // effective date

    cert_trust_list.emplace(vector<der>{ms_catalogue_list_member, nullptr});
//     SEQUENCE (17 elem) // entries
//     [0] (1 elem) // key-value store

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
