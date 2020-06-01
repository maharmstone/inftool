#include <string>
#include <vector>
#include <variant>
#include <iostream>

using namespace std;

enum class der_type {
    sequence,
    integer,
    ia5string
};

#define DER_INTEGER     0x02
#define DER_IA5STRING   0x16
#define DER_SEQUENCE    0x30

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

class der {
public:
    der(const vector<der>& s) : type(der_type::sequence), value(s) { }
    der(int64_t v) : type(der_type::integer), value(v) { }
    der(const string_view& sv) : type(der_type::ia5string), value(string(sv)) { }

    template<typename T>
    void emplace(const T& t) {
        if (type != der_type::sequence)
            throw runtime_error("Cannot call der::push_back unless SEQUENCE.");

        get<vector<der>>(value).emplace_back(t);
    }

    void dump(ostream& out) const {
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
        }
    }

    unsigned int length() const {
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

            default:
                return 0;
        }
    }

    der_type type;
    variant<vector<der>, int64_t, string> value;
};

static void main2() {
    der test(vector<der>{});

    test.emplace(5);
    test.emplace("Anybody there?");

    test.dump(cout);
}

int main() {
    try {
        main2();
    } catch (const exception& e) {
        cerr << e.what() << endl;
    }
}
