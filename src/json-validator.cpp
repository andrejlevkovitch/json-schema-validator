/*
 * JSON schema validator for JSON for modern C++
 *
 * Copyright (c) 2016-2019 Patrick Boettcher <p@yai.se>.
 *
 * SPDX-License-Identifier: MIT
 *
 */
#include <nlohmann/json-schema.hpp>

#include "json-patch.hpp"

#include <memory>
#include <set>
#include <sstream>

#include "constraints.hpp"
#include <list>

using nlohmann::json;
using nlohmann::json_patch;
using nlohmann::json_uri;
using nlohmann::json_schema::root_schema;
using namespace nlohmann::json_schema;

using constraint = nlohmann::constraint;
using constraints = std::list<constraint>;
using constraint_error = nlohmann::constraint_error;
using constraint_factory = nlohmann::constraint_factory;

#ifdef JSON_SCHEMA_BOOST_REGEX
#	include <boost/regex.hpp>
#	define REGEX_NAMESPACE boost
#elif defined(JSON_SCHEMA_NO_REGEX)
#	define NO_STD_REGEX
#else
#	include <regex>
#	define REGEX_NAMESPACE std
#endif

namespace
{

static const json EmptyDefault{};

static std::map<std::string, std::function<constraint(const json &)>> generic_keywords{
    {"enum", constraint_factory::create_enum},
    {"const", constraint_factory::create_const},
};

static std::map<std::string, std::function<constraint(const json &)>> numeric_keywords{
    {"minimum", constraint_factory::create_minimum},
    {"maximum", constraint_factory::create_maximum},
    {"exclusiveMinimum", constraint_factory::create_exclusiveMinimum},
    {"exclusiveMaximum", constraint_factory::create_exclusiveMaximum},
    {"multipleOf", constraint_factory::create_multipleOf},
};

static std::map<std::string, std::function<constraint(const json &)>> string_keywords{
    {"minLength", constraint_factory::create_minLength},
    {"maxLength", constraint_factory::create_maxLength},
    {"pattern", constraint_factory::create_pattern},
};

static std::map<std::string, std::function<constraint(const json &)>> array_keywords{
    {"minItems", constraint_factory::create_minItems},
    {"maxItems", constraint_factory::create_maxItems},
    {"uniqueItems", constraint_factory::create_uniqueItems},
};

static std::map<std::string, std::function<constraint(const json &)>> object_keywords{
    {"minProperties", constraint_factory::create_minProperties},
    {"maxProperties", constraint_factory::create_maxProperties},
    //  {"required", constraint_factory::create_required},
};

class schema
{
protected:
	root_schema *root_;

public:
	virtual ~schema() = default;

	schema(root_schema *root)
	    : root_(root) {}

	virtual void validate(const json::json_pointer &ptr, const json &instance, json_patch &patch, error_handler &e) const = 0;

	virtual const json &defaultValue(const json::json_pointer &, const json &, error_handler &) const
	{
		return EmptyDefault;
	}

	static std::shared_ptr<schema> make(json &schema,
	                                    root_schema *root,
	                                    const std::vector<std::string> &key,
	                                    std::vector<nlohmann::json_uri> uris);
};

class schema_ref : public schema
{
	const std::string id_;
	std::weak_ptr<schema> target_;

	void validate(const json::json_pointer &ptr, const json &instance, json_patch &patch, error_handler &e) const final
	{
		auto target = target_.lock();

		if (target)
			target->validate(ptr, instance, patch, e);
		else
			e.error(ptr, instance, "unresolved or freed schema-reference " + id_);
	}

	const json &defaultValue(const json::json_pointer &ptr, const json &instance, error_handler &e) const override
	{
		auto target = target_.lock();

		if (target)
			return target->defaultValue(ptr, instance, e);
		else
			e.error(ptr, instance, "unresolved or freed schema-reference " + id_);

		return EmptyDefault;
	}

public:
	schema_ref(const std::string &id, root_schema *root)
	    : schema(root), id_(id) {}

	const std::string &id() const { return id_; }
	void set_target(const std::shared_ptr<schema> &target) { target_ = target; }
};

} // namespace

namespace nlohmann
{
namespace json_schema
{

class root_schema : public schema
{
	schema_loader loader_;
	format_checker format_check_;

	std::shared_ptr<schema> root_;

	struct schema_file {
		std::map<std::string, std::shared_ptr<schema>> schemas;
		std::map<std::string, std::shared_ptr<schema_ref>> unresolved; // contains all unresolved references from any other file seen during parsing
		json unknown_keywords;
	};

	// location as key
	std::map<std::string, schema_file> files_;

	schema_file &get_or_create_file(const std::string &loc)
	{
		auto file = files_.lower_bound(loc);
		if (file != files_.end() && !(files_.key_comp()(loc, file->first)))
			return file->second;
		else
			return files_.insert(file, {loc, {}})->second;
	}

public:
	root_schema(schema_loader &&loader,
	            format_checker &&format)
	    : schema(this), loader_(std::move(loader)), format_check_(std::move(format)) {}

	format_checker &format_check() { return format_check_; }

	void insert(const json_uri &uri, const std::shared_ptr<schema> &s)
	{
		auto &file = get_or_create_file(uri.location());
		auto found = file.schemas.lower_bound(uri.fragment());
		if (found != file.schemas.end() && !(file.schemas.key_comp()(uri.fragment(), found->first))) {
			throw std::invalid_argument("schema with " + uri.to_string() + " already inserted");
			return;
		}

		file.schemas.insert({uri.fragment(), s});

		// was someone referencing this newly inserted schema?
		auto unresolved = file.unresolved.find(uri.fragment());
		if (unresolved != file.unresolved.end()) {
			unresolved->second->set_target(s);
			file.unresolved.erase(unresolved);
		}
	}

	void insert_unknown_keyword(const json_uri &uri, const std::string &key, json &value)
	{
		auto &file = get_or_create_file(uri.location());
		auto new_uri = uri.append(key);
		auto fragment = new_uri.pointer();

		// is there a reference looking for this unknown-keyword, which is thus no longer a unknown keyword but a schema
		auto unresolved = file.unresolved.find(fragment);
		if (unresolved != file.unresolved.end())
			schema::make(value, this, {}, {{new_uri}});
		else // no, nothing ref'd it, keep for later
			file.unknown_keywords[fragment] = value;

		// recursively add possible subschemas of unknown keywords
		if (value.type() == json::value_t::object)
			for (auto &subsch : value.items())
				insert_unknown_keyword(new_uri, subsch.key(), subsch.value());
	}

	std::shared_ptr<schema> get_or_create_ref(const json_uri &uri)
	{
		auto &file = get_or_create_file(uri.location());

		// existing schema
		auto found = file.schemas.find(uri.fragment());
		if (found != file.schemas.end())
			return found->second;

		// referencing an unknown keyword, turn it into schema
		//
		// an unknown keyword can only be referenced by a json-pointer,
		// not by a plain name fragment
		if (uri.pointer() != "") {
			try {
				auto &subschema = file.unknown_keywords.at(uri.pointer()); // null is returned if not existing
				auto s = schema::make(subschema, this, {}, {{uri}});       //  A JSON Schema MUST be an object or a boolean.
				if (s) {                                                   // nullptr if invalid schema, e.g. null
					file.unknown_keywords.erase(uri.fragment());
					return s;
				}
			} catch (nlohmann::detail::out_of_range &) { // at() did not find it
			}
		}

		// get or create a schema_ref
		auto r = file.unresolved.lower_bound(uri.fragment());
		if (r != file.unresolved.end() && !(file.unresolved.key_comp()(uri.fragment(), r->first))) {
			return r->second; // unresolved, already seen previously - use existing reference
		} else {
			return file.unresolved.insert(r,
			                              {uri.fragment(), std::make_shared<schema_ref>(uri.to_string(), this)})
			    ->second; // unresolved, create reference
		}
	}

	void set_root_schema(json a_schema)
	{
		files_.clear();
		root_ = schema::make(a_schema, this, {}, {{"#"}});

		// load all files which have not yet been loaded
		do {
			bool new_schema_loaded = false;

			// files_ is modified during parsing, iterators are invalidated
			std::vector<std::string> locations;
			for (auto &file : files_)
				locations.push_back(file.first);

			for (auto &loc : locations) {
				if (files_[loc].schemas.size() == 0) { // nothing has been loaded for this file
					if (loader_) {
						json sch;

						loader_(loc, sch);

						schema::make(sch, this, {}, {{loc}});
						new_schema_loaded = true;
					} else {
						throw std::invalid_argument("external schema reference '" + loc + "' needs loading, but no loader callback given");
					}
				}
			}

			if (!new_schema_loaded) // if no new schema loaded, no need to try again
				break;
		} while (1);

		for (const auto &file : files_)
			if (file.second.unresolved.size() != 0)
				throw std::invalid_argument("after all files have been parsed, '" +
				                            (file.first == "" ? "<root>" : file.first) +
				                            "' has still undefined references.");
	}

	void validate(const json::json_pointer &ptr, const json &instance, json_patch &patch, error_handler &e) const final
	{
		if (root_)
			root_->validate(ptr, instance, patch, e);
		else
			e.error(ptr, "", "no root schema has yet been set for validating an instance");
	}

	const json &defaultValue(const json::json_pointer &ptr, const json &instance, error_handler &e) const override
	{
		if (root_)
			return root_->defaultValue(ptr, instance, e);
		else
			e.error(ptr, "", "no root schema has yet been set for validating an instance");

		return EmptyDefault;
	}
};

} // namespace json_schema
} // namespace nlohmann

namespace
{

class first_error_handler : public error_handler
{
public:
	bool error_{false};
	json::json_pointer ptr_;
	json instance_;
	std::string message_;

	void error(const json::json_pointer &ptr, const json &instance, const std::string &message) override
	{
		if (*this)
			return;
		error_ = true;
		ptr_ = ptr;
		instance_ = instance;
		message_ = message;
	}

	operator bool() const { return error_; }
};

class logical_not : public schema
{
	std::shared_ptr<schema> subschema_;

	void validate(const json::json_pointer &ptr, const json &instance, json_patch &patch, error_handler &e) const final
	{
		first_error_handler esub;
		subschema_->validate(ptr, instance, patch, esub);

		if (!esub)
			e.error(ptr, instance, "the subschema has succeeded, but it is required to not validate");
	}

	const json &defaultValue(const json::json_pointer &ptr, const json &instance, error_handler &e) const override
	{
		return subschema_->defaultValue(ptr, instance, e);
	}

public:
	logical_not(json &sch,
	            root_schema *root,
	            const std::vector<nlohmann::json_uri> &uris)
	    : schema(root)
	{
		subschema_ = schema::make(sch, root, {"not"}, uris);
	}
};

enum logical_combination_types {
	allOf,
	anyOf,
	oneOf
};

template <enum logical_combination_types combine_logic>
class logical_combination : public schema
{
	std::vector<std::shared_ptr<schema>> subschemata_;

	void validate(const json::json_pointer &ptr, const json &instance, json_patch &patch, error_handler &e) const final
	{
		size_t count = 0;

		for (auto &s : subschemata_) {
			first_error_handler esub;
			s->validate(ptr, instance, patch, esub);
			if (!esub)
				count++;

			if (is_validate_complete(instance, ptr, e, esub, count))
				return;
		}

		// could accumulate esub details for anyOf and oneOf, but not clear how to select which subschema failure to report
		// or how to report multiple such failures
		if (count == 0)
			e.error(ptr, instance, "no subschema has succeeded, but one of them is required to validate");
	}

	// specialized for each of the logical_combination_types
	static const std::string key;
	static bool is_validate_complete(const json &, const json::json_pointer &, error_handler &, const first_error_handler &, size_t);

public:
	logical_combination(json &sch,
	                    root_schema *root,
	                    const std::vector<nlohmann::json_uri> &uris)
	    : schema(root)
	{
		size_t c = 0;
		for (auto &subschema : sch)
			subschemata_.push_back(schema::make(subschema, root, {key, std::to_string(c++)}, uris));

		// value of allOf, anyOf, and oneOf "MUST be a non-empty array"
		// TODO error/throw? when subschemata_.empty()
	}
};

template <>
const std::string logical_combination<allOf>::key = "allOf";
template <>
const std::string logical_combination<anyOf>::key = "anyOf";
template <>
const std::string logical_combination<oneOf>::key = "oneOf";

template <>
bool logical_combination<allOf>::is_validate_complete(const json &, const json::json_pointer &, error_handler &e, const first_error_handler &esub, size_t)
{
	if (esub)
		e.error(esub.ptr_, esub.instance_, "at least one subschema has failed, but all of them are required to validate - " + esub.message_);
	return esub;
}

template <>
bool logical_combination<anyOf>::is_validate_complete(const json &, const json::json_pointer &, error_handler &, const first_error_handler &, size_t count)
{
	return count == 1;
}

template <>
bool logical_combination<oneOf>::is_validate_complete(const json &instance, const json::json_pointer &ptr, error_handler &e, const first_error_handler &, size_t count)
{
	if (count > 1)
		e.error(ptr, instance, "more than one subschema has succeeded, but exactly one of them is required to validate");
	return count > 1;
}

class type_schema : public schema
{
	json defaultValue_{};
	std::vector<std::shared_ptr<schema>> type_;
	std::vector<std::shared_ptr<schema>> logic_;

	constraints constraints_;

	static std::shared_ptr<schema> make(json &schema,
	                                    json::value_t type,
	                                    root_schema *,
	                                    const std::vector<nlohmann::json_uri> &);

	std::shared_ptr<schema> if_, then_, else_;

	const json &defaultValue(const json::json_pointer &, const json &, error_handler &) const override
	{
		return defaultValue_;
	}

	void validate(const json::json_pointer &ptr, const json &instance, json_patch &patch, error_handler &e) const override final
	{
		// depending on the type of instance run the type specific validator - if present
		auto type = type_[(uint8_t) instance.type()];

		if (type)
			type->validate(ptr, instance, patch, e);
		else
			e.error(ptr, instance, "unexpected instance type");

		for (const constraint &cns : constraints_) {
			constraint_error err = cns(instance);
			if (err.fail()) {
				e.error(ptr, instance, err.msg());
			}
		}

		for (auto l : logic_)
			l->validate(ptr, instance, patch, e);

		if (if_) {
			first_error_handler err;

			if_->validate(ptr, instance, patch, err);
			if (!err) {
				if (then_)
					then_->validate(ptr, instance, patch, e);
			} else {
				if (else_)
					else_->validate(ptr, instance, patch, e);
			}
		}
	}

public:
	type_schema(json &sch,
	            root_schema *root,
	            const std::vector<nlohmann::json_uri> &uris)
	    : schema(root), type_((uint8_t) json::value_t::discarded + 1)
	{
		// association between JSON-schema-type and NLohmann-types
		static const std::vector<std::pair<std::string, json::value_t>> schema_types = {
		    {"null", json::value_t::null},
		    {"object", json::value_t::object},
		    {"array", json::value_t::array},
		    {"string", json::value_t::string},
		    {"boolean", json::value_t::boolean},
		    {"integer", json::value_t::number_integer},
		    {"number", json::value_t::number_float},
		};

		auto attr = sch.find("type");
		if (attr == sch.end()) // no type field means all sub-types possible
			for (auto &t : schema_types)
				type_[(uint8_t) t.second] = type_schema::make(sch, t.second, root, uris);
		else {
			switch (attr.value().type()) { // "type": "type"

			case json::value_t::string: {
				auto schema_type = attr.value().get<std::string>();
				for (auto &t : schema_types)
					if (t.first == schema_type)
						type_[(uint8_t) t.second] = type_schema::make(sch, t.second, root, uris);
			} break;

			case json::value_t::array: // "type": ["type1", "type2"]
				for (auto &schema_type : attr.value())
					for (auto &t : schema_types)
						if (t.first == schema_type)
							type_[(uint8_t) t.second] = type_schema::make(sch, t.second, root, uris);
				break;

			default:
				break;
			}

			sch.erase(attr);
		}

		const auto defaultAttr = sch.find("default");
		if (defaultAttr != sch.end()) {
			defaultValue_ = defaultAttr.value();
		}

		// with nlohmann::json float instance (but number in schema-definition) can be seen as unsigned or integer -
		// reuse the number-validator for integer values as well, if they have not been specified explicitly
		if (type_[(uint8_t) json::value_t::number_float] && !type_[(uint8_t) json::value_t::number_integer])
			type_[(uint8_t) json::value_t::number_integer] = type_[(uint8_t) json::value_t::number_float];

		// #54: JSON-schema does not differentiate between unsigned and signed integer - nlohmann::json does
		// we stick with JSON-schema: use the integer-validator if instance-value is unsigned
		type_[(uint8_t) json::value_t::number_unsigned] = type_[(uint8_t) json::value_t::number_integer];

		for (const auto &keyword : generic_keywords) {
			auto found = sch.find(keyword.first);
			if (found != sch.end()) {
				constraints_.emplace_back(keyword.second(found.value()));
			}
		}

		attr = sch.find("not");
		if (attr != sch.end()) {
			logic_.push_back(std::make_shared<logical_not>(attr.value(), root, uris));
			sch.erase(attr);
		}

		attr = sch.find("allOf");
		if (attr != sch.end()) {
			logic_.push_back(std::make_shared<logical_combination<allOf>>(attr.value(), root, uris));
			sch.erase(attr);
		}

		attr = sch.find("anyOf");
		if (attr != sch.end()) {
			logic_.push_back(std::make_shared<logical_combination<anyOf>>(attr.value(), root, uris));
			sch.erase(attr);
		}

		attr = sch.find("oneOf");
		if (attr != sch.end()) {
			logic_.push_back(std::make_shared<logical_combination<oneOf>>(attr.value(), root, uris));
			sch.erase(attr);
		}

		attr = sch.find("if");
		if (attr != sch.end()) {
			auto attr_then = sch.find("then");
			auto attr_else = sch.find("else");

			if (attr_then != sch.end() || attr_else != sch.end()) {
				if_ = schema::make(attr.value(), root, {"if"}, uris);

				if (attr_then != sch.end()) {
					then_ = schema::make(attr_then.value(), root, {"then"}, uris);
					sch.erase(attr_then);
				}

				if (attr_else != sch.end()) {
					else_ = schema::make(attr_else.value(), root, {"else"}, uris);
					sch.erase(attr_else);
				}
			}
			sch.erase(attr);
		}
	}
};

class string : public schema
{
	constraints constraints_;

	std::pair<bool, std::string> format_;

	void validate(const json::json_pointer &ptr, const json &instance, json_patch &, error_handler &e) const override
	{
		for (const constraint &cns : constraints_) {
			constraint_error err = cns(instance);
			if (err.fail()) {
				e.error(ptr, instance, err.msg());
			}
		}

		if (format_.first) {
			if (root_->format_check() == nullptr)
				e.error(ptr, instance, std::string("a format checker was not provided but a format keyword for this string is present: ") + format_.second);
			else {
				try {
					root_->format_check()(format_.second, instance);
				} catch (const std::exception &ex) {
					e.error(ptr, instance, std::string("format-checking failed: ") + ex.what());
				}
			}
		}
	}

public:
	string(json &sch, root_schema *root)
	    : schema(root)
	{
		for (const auto &keyword : string_keywords) {
			auto found = sch.find(keyword.first);
			if (found != sch.end()) {
				constraints_.emplace_back(keyword.second(found.value()));
				sch.erase(found);
			}
		}

		auto attr = sch.find("format");
		if (attr != sch.end()) {
			format_ = {true, attr.value()};
			sch.erase(attr);
		}
	}
};

class numeric : public schema
{
	constraints constraints_;

	void validate(const json::json_pointer &ptr, const json &instance, json_patch &, error_handler &e) const override
	{
		for (const constraint &cns : constraints_) {
			constraint_error err = cns(instance);
			if (err.fail()) {
				e.error(ptr, instance, err.msg());
			}
		}
	}

public:
	numeric(json &sch, root_schema *root)
	    : schema(root)
	{
		for (const auto &keyword : numeric_keywords) {
			auto found = sch.find(keyword.first);
			if (found != sch.end()) {
				constraints_.emplace_back(keyword.second(found.value()));
				sch.erase(found);
			}
		}
	}
};

class null : public schema
{
	void validate(const json::json_pointer &, const json &, json_patch &, error_handler &) const override {}

public:
	null(json &, root_schema *root)
	    : schema(root) {}
};

class boolean_type : public schema
{
	void validate(const json::json_pointer &, const json &, json_patch &, error_handler &) const override {}

public:
	boolean_type(json &, root_schema *root)
	    : schema(root) {}
};

class boolean : public schema
{
	bool true_;
	void validate(const json::json_pointer &ptr, const json &instance, json_patch &, error_handler &e) const override
	{
		if (!true_) { // false schema
			// empty array
			//switch (instance.type()) {
			//case json::value_t::array:
			//	if (instance.size() != 0) // valid false-schema
			//		e.error(ptr, instance, "false-schema required empty array");
			//	return;
			//}

			e.error(ptr, instance, "instance invalid as per false-schema");
		}
	}

public:
	boolean(json &sch, root_schema *root)
	    : schema(root), true_(sch) {}
};

class required : public schema
{
	const std::vector<std::string> required_;

	void validate(const json::json_pointer &ptr, const json &instance, json_patch &, error_handler &e) const override final
	{
		for (auto &r : required_)
			if (instance.find(r) == instance.end())
				e.error(ptr, instance, "required property '" + r + "' not found in object as a dependency");
	}

public:
	required(const std::vector<std::string> &r, root_schema *root)
	    : schema(root), required_(r) {}
};

class object : public schema
{
	constraints constraints_;
	std::vector<std::string> required_;

	std::map<std::string, std::shared_ptr<schema>> properties_;
#ifndef NO_STD_REGEX
	std::vector<std::pair<REGEX_NAMESPACE::regex, std::shared_ptr<schema>>> patternProperties_;
#endif
	std::shared_ptr<schema> additionalProperties_;

	std::map<std::string, std::shared_ptr<schema>> dependencies_;

	std::shared_ptr<schema> propertyNames_;

	void validate(const json::json_pointer &ptr, const json &instance, json_patch &patch, error_handler &e) const override
	{
		for (const constraint &cns : constraints_) {
			constraint_error err = cns(instance);
			if (err.fail()) {
				e.error(ptr, instance, err.msg());
			}
		}

		for (auto &r : required_)
			if (instance.find(r) == instance.end())
				e.error(ptr, instance, "required property '" + r + "' not found in object");

		// for each property in instance
		for (auto &p : instance.items()) {
			if (propertyNames_)
				propertyNames_->validate(ptr, p.key(), patch, e);

			bool a_prop_or_pattern_matched = false;
			auto schema_p = properties_.find(p.key());
			// check if it is in "properties"
			if (schema_p != properties_.end()) {
				a_prop_or_pattern_matched = true;
				schema_p->second->validate(ptr / p.key(), p.value(), patch, e);
			}

#ifndef NO_STD_REGEX
			// check all matching patternProperties
			for (auto &schema_pp : patternProperties_)
				if (REGEX_NAMESPACE::regex_search(p.key(), schema_pp.first)) {
					a_prop_or_pattern_matched = true;
					schema_pp.second->validate(ptr / p.key(), p.value(), patch, e);
				}
#endif

			// check additionalProperties as a last resort
			if (!a_prop_or_pattern_matched && additionalProperties_) {
				first_error_handler additional_prop_err;
				additionalProperties_->validate(ptr / p.key(), p.value(), patch, additional_prop_err);
				if (additional_prop_err)
					e.error(ptr, instance, "validation failed for additional property '" + p.key() + "': " + additional_prop_err.message_);
			}
		}

		// reverse search
		for (auto const &prop : properties_) {
			const auto finding = instance.find(prop.first);
			if (instance.end() == finding) { // if the prop is not in the instance
				const auto &defaultValue = prop.second->defaultValue(ptr, instance, e);
				if (!defaultValue.empty()) { // if default value is available
					patch.add((ptr / prop.first), defaultValue);
				}
			}
		}

		for (auto &dep : dependencies_) {
			auto prop = instance.find(dep.first);
			if (prop != instance.end())                                    // if dependency-property is present in instance
				dep.second->validate(ptr / dep.first, instance, patch, e); // validate
		}
	}

public:
	object(json &sch,
	       root_schema *root,
	       const std::vector<nlohmann::json_uri> &uris)
	    : schema(root)
	{
		for (const auto &keyword : object_keywords) {
			auto found = sch.find(keyword.first);
			if (found != sch.end()) {
				constraints_.emplace_back(keyword.second(found.value()));
				sch.erase(found);
			}
		}

		auto attr = sch.find("required");
		if (attr != sch.end()) {
			required_ = attr.value().get<std::vector<std::string>>();
			sch.erase(attr);
		}

		attr = sch.find("properties");
		if (attr != sch.end()) {
			for (auto prop : attr.value().items())
				properties_.insert(
				    std::make_pair(
				        prop.key(),
				        schema::make(prop.value(), root, {"properties", prop.key()}, uris)));
			sch.erase(attr);
		}

#ifndef NO_STD_REGEX
		attr = sch.find("patternProperties");
		if (attr != sch.end()) {
			for (auto prop : attr.value().items())
				patternProperties_.push_back(
				    std::make_pair(
				        REGEX_NAMESPACE::regex(prop.key(), REGEX_NAMESPACE::regex::ECMAScript),
				        schema::make(prop.value(), root, {prop.key()}, uris)));
			sch.erase(attr);
		}
#endif

		attr = sch.find("additionalProperties");
		if (attr != sch.end()) {
			additionalProperties_ = schema::make(attr.value(), root, {"additionalProperties"}, uris);
			sch.erase(attr);
		}

		attr = sch.find("dependencies");
		if (attr != sch.end()) {
			for (auto &dep : attr.value().items())
				switch (dep.value().type()) {
				case json::value_t::array:
					dependencies_.emplace(dep.key(),
					                      std::make_shared<required>(
					                          dep.value().get<std::vector<std::string>>(), root));
					break;

				default:
					dependencies_.emplace(dep.key(),
					                      schema::make(dep.value(), root, {"dependencies", dep.key()}, uris));
					break;
				}
			sch.erase(attr);
		}

		attr = sch.find("propertyNames");
		if (attr != sch.end()) {
			propertyNames_ = schema::make(attr.value(), root, {"propertyNames"}, uris);
			sch.erase(attr);
		}
	}
};

class array : public schema
{
	constraints constraints_;

	std::shared_ptr<schema> items_schema_;

	std::vector<std::shared_ptr<schema>> items_;
	std::shared_ptr<schema> additionalItems_;

	std::shared_ptr<schema> contains_;

	void validate(const json::json_pointer &ptr, const json &instance, json_patch &patch, error_handler &e) const override
	{
		for (const constraint &cns : constraints_) {
			constraint_error err = cns(instance);
			if (err.fail()) {
				e.error(ptr, instance, err.msg());
			}
		}

		size_t index = 0;
		if (items_schema_)
			for (auto &i : instance) {
				items_schema_->validate(ptr / index, i, patch, e);
				index++;
			}
		else {
			auto item = items_.cbegin();
			for (auto &i : instance) {
				std::shared_ptr<schema> item_validator;
				if (item == items_.cend())
					item_validator = additionalItems_;
				else {
					item_validator = *item;
					item++;
				}

				if (!item_validator)
					break;

				item_validator->validate(ptr / index, i, patch, e);
			}
		}

		if (contains_) {
			bool contained = false;
			for (auto &item : instance) {
				first_error_handler local_e;
				contains_->validate(ptr, item, patch, local_e);
				if (!local_e) {
					contained = true;
					break;
				}
			}
			if (!contained)
				e.error(ptr, instance, "array does not contain required element as per 'contains'");
		}
	}

public:
	array(json &sch, root_schema *root, const std::vector<nlohmann::json_uri> &uris)
	    : schema(root)
	{
		for (const auto &keyword : array_keywords) {
			auto found = sch.find(keyword.first);
			if (found != sch.end()) {
				constraints_.emplace_back(keyword.second(found.value()));
				sch.erase(found);
			}
		}

		auto attr = sch.find("items");
		if (attr != sch.end()) {

			if (attr.value().type() == json::value_t::array) {
				size_t c = 0;
				for (auto &subsch : attr.value())
					items_.push_back(schema::make(subsch, root, {"items", std::to_string(c++)}, uris));

				auto attr_add = sch.find("additionalItems");
				if (attr_add != sch.end()) {
					additionalItems_ = schema::make(attr_add.value(), root, {"additionalItems"}, uris);
					sch.erase(attr_add);
				}

			} else if (attr.value().type() == json::value_t::object ||
			           attr.value().type() == json::value_t::boolean)
				items_schema_ = schema::make(attr.value(), root, {"items"}, uris);

			sch.erase(attr);
		}

		attr = sch.find("contains");
		if (attr != sch.end()) {
			contains_ = schema::make(attr.value(), root, {"contains"}, uris);
			sch.erase(attr);
		}
	}
};

std::shared_ptr<schema> type_schema::make(json &schema,
                                          json::value_t type,
                                          root_schema *root,
                                          const std::vector<nlohmann::json_uri> &uris)
{
	switch (type) {
	case json::value_t::null:
		return std::make_shared<null>(schema, root);

	case json::value_t::number_unsigned:
	case json::value_t::number_integer:
	case json::value_t::number_float:
		return std::make_shared<numeric>(schema, root);
	case json::value_t::string:
		return std::make_shared<string>(schema, root);
	case json::value_t::boolean:
		return std::make_shared<boolean_type>(schema, root);
	case json::value_t::object:
		return std::make_shared<object>(schema, root, uris);
	case json::value_t::array:
		return std::make_shared<array>(schema, root, uris);

	case json::value_t::discarded: // not a real type - silence please
		break;

	case json::value_t::binary: // not available for json
		break;
	}
	return nullptr;
}
} // namespace

namespace
{

std::shared_ptr<schema> schema::make(json &schema,
                                     root_schema *root,
                                     const std::vector<std::string> &keys,
                                     std::vector<nlohmann::json_uri> uris)
{
	// remove URIs which contain plain name identifiers, as sub-schemas cannot be referenced
	for (auto uri = uris.begin(); uri != uris.end();)
		if (uri->identifier() != "")
			uri = uris.erase(uri);
		else
			uri++;

	// append to all URIs the keys for this sub-schema
	for (auto &key : keys)
		for (auto &uri : uris)
			uri = uri.append(key);

	std::shared_ptr<::schema> sch;

	// boolean schema
	if (schema.type() == json::value_t::boolean)
		sch = std::make_shared<boolean>(schema, root);
	else if (schema.type() == json::value_t::object) {

		auto attr = schema.find("$id"); // if $id is present, this schema can be referenced by this ID
		                                // as an additional URI
		if (attr != schema.end()) {
			if (std::find(uris.begin(),
			              uris.end(),
			              attr.value().get<std::string>()) == uris.end())
				uris.push_back(uris.back().derive(attr.value())); // so add it to the list if it is not there already
			schema.erase(attr);
		}

		attr = schema.find("definitions");
		if (attr != schema.end()) {
			for (auto &def : attr.value().items())
				schema::make(def.value(), root, {"definitions", def.key()}, uris);
			schema.erase(attr);
		}

		attr = schema.find("$ref");
		if (attr != schema.end()) { // this schema is a reference
			// the last one on the uri-stack is the last id seen before coming here,
			// so this is the origial URI for this reference, the $ref-value has thus be resolved from it
			auto id = uris.back().derive(attr.value());
			sch = root->get_or_create_ref(id);
			schema.erase(attr);
		} else {
			sch = std::make_shared<type_schema>(schema, root, uris);
		}

		schema.erase("$schema");
		schema.erase("default");
		schema.erase("title");
		schema.erase("description");
	} else {
		throw std::invalid_argument("invalid JSON-type for a schema for " + uris[0].to_string() + ", expected: boolean or object");
	}

	for (auto &uri : uris) { // for all URIs this schema is referenced by
		root->insert(uri, sch);

		if (schema.type() == json::value_t::object)
			for (auto &u : schema.items())
				root->insert_unknown_keyword(uri, u.key(), u.value()); // insert unknown keywords for later reference
	}
	return sch;
}

class throwing_error_handler : public error_handler
{
	void error(const json::json_pointer &ptr, const json &instance, const std::string &message) override
	{
		throw std::invalid_argument(std::string("At ") + ptr.to_string() + " of " + instance.dump() + " - " + message + "\n");
	}
};

} // namespace

namespace nlohmann
{
namespace json_schema
{

json_validator::json_validator(schema_loader loader,
                               format_checker format)
    : root_(std::unique_ptr<root_schema>(new root_schema(std::move(loader), std::move(format))))
{
}

json_validator::json_validator(const json &schema, schema_loader loader, format_checker format)
    : json_validator(std::move(loader), std::move(format))
{
	set_root_schema(schema);
}

json_validator::json_validator(json &&schema, schema_loader loader, format_checker format)
    : json_validator(std::move(loader), std::move(format))
{
	set_root_schema(std::move(schema));
}

// move constructor, destructor and move assignment operator can be defaulted here
// where root_schema is a complete type
json_validator::json_validator(json_validator &&) = default;
json_validator::~json_validator() = default;
json_validator &json_validator::operator=(json_validator &&) = default;

void json_validator::set_root_schema(const json &schema)
{
	root_->set_root_schema(schema);
}

void json_validator::set_root_schema(json &&schema)
{
	root_->set_root_schema(std::move(schema));
}

json json_validator::validate(const json &instance) const
{
	throwing_error_handler err;
	return validate(instance, err);
}

json json_validator::validate(const json &instance, error_handler &err) const
{
	json::json_pointer ptr;
	json_patch patch;
	root_->validate(ptr, instance, patch, err);
	return patch;
}

} // namespace json_schema
} // namespace nlohmann
