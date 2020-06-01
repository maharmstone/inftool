#include <string>
#include <vector>
#include <variant>
#include <iostream>
#include <chrono>

enum class der_type {
    sequence,
    integer,
    ia5string,
    obj_id,
    context_specific,
    set,
    null,
    octet_string,
    utc_time
};

#define DER_INTEGER             0x02
#define DER_OCTET_STRING        0x04
#define DER_NULL                0x05
#define DER_OBJ_ID              0x06
#define DER_IA5STRING           0x16
#define DER_UTCTIME             0x17
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

    std::string s;
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

    template<typename T>
    void emplace(const T& t) {
        if (type != der_type::sequence)
            throw std::runtime_error("Cannot call der::push_back unless SEQUENCE.");

        std::get<std::vector<der>>(value).emplace_back(t);
    }

    void dump(std::ostream& out) const;

    unsigned int length() const;

    der_type type;
    std::variant<std::vector<der>, int64_t, std::string, obj_id, context_specific,
                 der_set, std::chrono::system_clock::time_point> value;
};
