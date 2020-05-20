// constraints.hpp

#pragma once

#include <functional>
#include <nlohmann/json-schema.hpp>
#include <nlohmann/json.hpp>

namespace nlohmann
{
class constraint_error final
{
public:
	constraint_error(bool ok, const std::string &msg) noexcept
	    : ok_{ok}, msg_{msg}
	{
	}

	constraint_error(bool ok, std::string &&msg) noexcept
	    : ok_{ok}, msg_{std::move(msg)}
	{
	}

	bool fail() const noexcept
	{
		return ok_ == false;
	}

	std::string msg() const noexcept
	{
		return msg_;
	}

private:
	bool ok_;
	std::string msg_;
};

/**\return true and empty string in case of success, false and error in case of failure
 */
using constraint = std::function<constraint_error(const nlohmann::json &json)>;

class constraint_factory
{
	using json = nlohmann::json;

public:
	/* numeric constraints */
	static constraint create_minimum(const json &schema_constraint);
	static constraint create_maximum(const json &schema_constraint);

	static constraint create_exclusiveMinimum(const json &schema_constraint);
	static constraint create_exclusiveMaximum(const json &schema_constraint);

	static constraint create_multipleOf(const json &schema_constraint);

	/* string constraints */
	static constraint create_minLength(const json &schema_constraint);
	static constraint create_maxLength(const json &schema_constraint);

	static constraint create_pattern(const json &schema_constraint);

	/* array constraints */
	static constraint create_minItems(const json &schema_constraint);
	static constraint create_maxItems(const json &schema_constraint);

	static constraint create_uniqueItems(const json &schema_constraint);

	/* object constraints */
	static constraint create_minProperties(const json &schema_constraint);
	static constraint create_maxProperties(const json &schema_constraint);

	static constraint create_required(const json &schema_constraint);

	/* generic constraints */
	static constraint create_enum(const json &schema_constraint);
	static constraint create_const(const json &schema_constraint);
};
} // namespace nlohmann
