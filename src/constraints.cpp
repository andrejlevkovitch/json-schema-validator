// constraints.cpp

#include "constraints.hpp"

#ifdef JSON_SCHEMA_BOOST_REGEX
#	include <boost/regex.hpp>
#	define REGEX_NAMESPACE boost
#elif defined(JSON_SCHEMA_NO_REGEX)
#	define NO_STD_REGEX
#else
#	include <regex>
#	define REGEX_NAMESPACE std
#endif

#define SUCCESS() \
	constraint_error { true, "" }

#define FAILURE(msg) \
	constraint_error { false, msg }

namespace nlohmann
{
/* numeric constraints */
constraint constraint_factory::create_minimum(const json &schema_constraint)
{
	double num_cns = schema_constraint;
	return constraint{[num_cns](const json &value) {
		double num_value = value;
		if (num_value >= num_cns) {
			return SUCCESS();
		}

		return FAILURE("instance is below minimum of " + std::to_string(num_cns));
	}};
}

constraint constraint_factory::create_maximum(const json &schema_constraint)
{
	double num_cns = schema_constraint;
	return constraint{[num_cns](const json &value) {
		double num_value = value;
		if (num_value <= num_cns) {
			return SUCCESS();
		}

		return FAILURE("instance exceeds maximum of " + std::to_string(num_cns));
	}};
}

constraint constraint_factory::create_exclusiveMinimum(const json &schema_constraint)
{
	double num_cns = schema_constraint;
	return constraint{[num_cns](const json &value) {
		double num_value = value;
		if (num_value > num_cns) {
			return SUCCESS();
		}

		return FAILURE("instance is below minimum of " + std::to_string(num_cns));
	}};
}

constraint constraint_factory::create_exclusiveMaximum(const json &schema_constraint)
{
	double num_cns = schema_constraint;
	return constraint{[num_cns](const json &value) {
		double num_value = value;
		if (num_value < num_cns) {
			return SUCCESS();
		}

		return FAILURE("instance exceeds maximum of " + std::to_string(num_cns));
	}};
}

// multipleOf - if the remainder of the division is 0 -> OK
bool violates_multiple_of(double x, double multiplyer)
{
	double res = std::remainder(x, multiplyer);
	double eps = std::nextafter(x, 0) - x;
	return std::fabs(res) > std::fabs(eps);
}

constraint constraint_factory::create_multipleOf(const json &schema_constraint)
{
	double num_cns = schema_constraint;
	return constraint{[num_cns](const json &value) {
		double num_value = value;
		if (violates_multiple_of(num_value, num_cns) == false) {
			return SUCCESS();
		}

		return FAILURE("instance is not a multiple of " + std::to_string(num_cns));
	}};
}

/* string constraints */
std::size_t utf8_length(const std::string &s)
{
	size_t len = 0;
	for (const unsigned char c : s)
		if ((c & 0xc0) != 0x80)
			len++;
	return len;
}

constraint constraint_factory::create_minLength(const json &schema_constraint)
{
	size_t min_len = schema_constraint;
	return constraint{[min_len](const json &value) {
		if (utf8_length(value) >= min_len) {
			return SUCCESS();
		}
		return FAILURE("instance is too short as per minLength: " + std::to_string(min_len));
	}};
}

constraint constraint_factory::create_maxLength(const json &schema_constraint)
{
	size_t max_len = schema_constraint;
	return constraint{[max_len](const json &value) {
		if (utf8_length(value) <= max_len) {
			return SUCCESS();
		}
		return FAILURE("instance is too long as per maxLength" + std::to_string(max_len));
	}};
}

constraint constraint_factory::create_pattern(const json &schema_constraint)
{
	std::string pattern = schema_constraint;
	REGEX_NAMESPACE::regex regex{pattern, REGEX_NAMESPACE::regex::ECMAScript};
	return constraint{[pattern, regex](const json &value) {
		if (REGEX_NAMESPACE::regex_search(value.get<std::string>(), regex)) {
			return SUCCESS();
		}
		return FAILURE("instance does not match regex pattern: " + pattern);
	}};
}

/* array constraints */
constraint constraint_factory::create_minItems(const json &schema_constraint)
{
	size_t min_len = schema_constraint;
	return constraint{[min_len](const json &value) {
		size_t cur_len = value.size();
		if (cur_len >= min_len) {
			return SUCCESS();
		}
		return FAILURE("array has too few items");
	}};
}

constraint constraint_factory::create_maxItems(const json &schema_constraint)
{
	size_t max_len = schema_constraint;
	return constraint{[max_len](const json &value) {
		size_t cur_len = value.size();
		if (cur_len <= max_len) {
			return SUCCESS();
		}
		return FAILURE("array has too many items");
	}};
}

constraint constraint_factory::create_uniqueItems(const json &schema_constraint)
{
	bool unique = schema_constraint;
	if (unique) {
		return constraint{[](const json &values) {
			for (auto it = values.begin(); it != values.end(); ++it) {
				auto v = std::find(std::next(it), values.end(), it.value());
				if (v != values.end()) {
					return FAILURE("items have to be unique for this array");
				}
			}
			return SUCCESS();
		}};
	} else {
		return constraint{[](const json &) { return SUCCESS(); }};
	}
}

/* object constraints */
constraint constraint_factory::create_minProperties(const json &schema_constraint)
{
	size_t min_len = schema_constraint;
	return constraint{[min_len](const json &value) {
		size_t cur_len = value.size();
		if (cur_len >= min_len) {
			return SUCCESS();
		}
		return FAILURE("too few properties");
	}};
}

constraint constraint_factory::create_maxProperties(const json &schema_constraint)
{
	size_t max_len = schema_constraint;
	return constraint{[max_len](const json &value) {
		size_t cur_len = value.size();
		if (cur_len <= max_len) {
			return SUCCESS();
		}
		return FAILURE("too many properties");
	}};
}

constraint constraint_factory::create_required(const json &schema_constraint)
{
	using string_list = std::vector<std::string>;

	string_list required_keys = schema_constraint.get<string_list>();
	return constraint{[required_keys](const json &value) {
		for (const std::string &key : required_keys) {
			if (value.contains(key) == false) {
				return FAILURE("required property '" + key + "' not found in object");
			}
		}
		return SUCCESS();
	}};
}

/* generic constrains */
constraint constraint_factory::create_enum(const json &schema_constraint)
{
	return constraint{[schema_constraint](const json &value) {
		for (const json &item : schema_constraint) {
			if (value == item) {
				return SUCCESS();
			}
		}
		return FAILURE("instance not found in required enum");
	}};
}

constraint constraint_factory::create_const(const json &schema_constraint)
{
	return constraint{[schema_constraint](const json &value) {
		if (schema_constraint == value) {
			return SUCCESS();
		}
		return FAILURE("instance not const");
	}};
}
} // namespace nlohmann
