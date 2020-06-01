#include <string>
#include <vector>
#include <variant>
#include <iostream>

enum class der_type {
    sequence,
    integer,
    ia5string
};

#define DER_INTEGER     0x02
#define DER_IA5STRING   0x16
#define DER_SEQUENCE    0x30

class der {
public:
    der(const std::vector<der>& s) : type(der_type::sequence), value(s) { }
    der(int64_t v) : type(der_type::integer), value(v) { }
    der(const std::string_view& sv) : type(der_type::ia5string), value(std::string(sv)) { }

    template<typename T>
    void emplace(const T& t) {
        if (type != der_type::sequence)
            throw std::runtime_error("Cannot call der::push_back unless SEQUENCE.");

        std::get<std::vector<der>>(value).emplace_back(t);
    }

    void dump(std::ostream& out) const;

    unsigned int length() const;

    der_type type;
    std::variant<std::vector<der>, int64_t, std::string> value;
};