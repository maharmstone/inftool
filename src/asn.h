#include <string>
#include <vector>
#include <variant>
#include <iostream>
#include <chrono>
#include <span>

enum class der_type {
    sequence,
    integer,
    ia5string,
    obj_id,
    context_specific,
    set,
    null,
    octet_string,
    utc_time,
    bmp_string,
    bit_string
};

#define DER_INTEGER             0x02
#define DER_BIT_STRING          0x03
#define DER_OCTET_STRING        0x04
#define DER_NULL                0x05
#define DER_OBJ_ID              0x06
#define DER_IA5STRING           0x16
#define DER_UTCTIME             0x17
#define DER_BMPSTRING           0x1e
#define DER_SEQUENCE            0x30
#define DER_SET                 0x31
#define DER_CONTEXT_SPECIFIC    0xa0

class obj_id {
public:
    obj_id(const std::initializer_list<unsigned int>& v) : nums(v) { }

    std::vector<unsigned int> nums;
};

class der;

class context_specific {
public:
    context_specific(const std::initializer_list<der>& v) : els(v) { }

    std::vector<der> els;
};

class der_set {
public:
    der_set(const std::initializer_list<der>& v) : els(v) { }

    std::vector<der> els;
};

class octet_string {
public:
    octet_string(const std::string& s) : s(s) { }
    octet_string(const std::u16string& us) : s((char*)us.data(), (us.length() + 1) * sizeof(char16_t)) { }
    octet_string(const std::span<uint8_t>& s) : s((char*)s.data(), s.size()) { }

    std::string s;
};

class bit_string {
public:
    bit_string(unsigned int bits, uint64_t value) : bits(bits), value(value) { }

    unsigned int bits;
    uint64_t value;
};

class der {
public:
    der(const std::vector<der>& s) : type(der_type::sequence), value(s) { }
    der(int64_t v) : type(der_type::integer), value(v) { }
    der(const std::string_view& sv) : type(der_type::ia5string), value(std::string(sv)) { }
    der(const obj_id& oid) : type(der_type::obj_id), value(oid) { }
    der(const context_specific& cs) : type(der_type::context_specific), value(cs) { }
    der(const der_set& set) : type(der_type::set), value(set) { }
    der(nullptr_t) : type(der_type::null) { }
    der(const octet_string& os) : type(der_type::octet_string), value(os.s) { }
    der(const std::chrono::system_clock::time_point& time) : type(der_type::utc_time), value(time) { }
    der(const std::u16string& us) : type(der_type::bmp_string), value(us) { }
    der(const bit_string& bs) : type(der_type::bit_string), value(bs) { }

    template<typename T>
    void emplace(const T& t) {
        switch (type) {
            case der_type::sequence:
                std::get<std::vector<der>>(value).emplace_back(t);
            break;

            case der_type::set:
                std::get<der_set>(value).els.emplace_back(t);
            break;

            default:
                throw std::runtime_error("Cannot call der::push_back unless SEQUENCE or SET.");
        }
    }

    void dump(std::ostream& out) const;

    unsigned int length() const;

    der_type type;
    std::variant<std::vector<der>, int64_t, std::string, obj_id, context_specific,
                 der_set, std::chrono::system_clock::time_point, std::u16string,
                 bit_string> value;
};
