#ifndef JSON_H
#define JSON_H

#include "rcd.h"

/// JSON type identifier. Basic types are:
///  o Object
///  o Array
///  o String
///  o Number
///  o Boolean
///  o Null
typedef enum json_type {
    JSON_NULL = 0,
    JSON_BOOL = 1,
    JSON_NUMBER = 2,
    JSON_STRING = 3,
    JSON_ARRAY = 4,
    JSON_OBJECT = 5,
} json_type_t;

typedef struct json_value {
    json_type_t type;
    union {
        bool bool_value;
        double number_value;
        fstr_t string_value;
        list(json_value_t)* array_value;
        dict(json_value_t)* object_value;
    };
} json_value_t;

/// A JSON value, together with a heap which owns all values and strings contained
/// in that value.
typedef struct json_tree {
    json_value_t value;
    lwt_heap_t* heap;
} json_tree_t;

/// Parse a string into a json_tree_t. Throws exception_arg on failure.
json_tree_t* json_parse(fstr_t str);

/// Stringify a JSON tree structure.
fstr_mem_t* json_stringify(json_value_t value);

void json_fail_missing_property(fstr_t prop_name);

#define json_null_value ((json_value_t){.type = JSON_NULL})
#define json_bool_value(x)   ((json_value_t){.type = JSON_BOOL,   .bool_value   = x})
#define json_number_value(x) ((json_value_t){.type = JSON_NUMBER, .number_value = x})
#define json_string_value(x) ((json_value_t){.type = JSON_STRING, .string_value = x})
#define json_array_value(x)  ((json_value_t){.type = JSON_ARRAY,  .array_value  = x})
#define json_object_value(x) ((json_value_t){.type = JSON_OBJECT, .object_value = x})

inline json_value_t json_new_object() {
    return json_object_value(new_dict(json_value_t));
}

/// Returns a number from a JSON value, throwing exception_arg if the type is wrong.
inline double json_get_number(json_value_t value) {
    if (value.type != JSON_NUMBER)
        throw(fstr("expected number in JSON"), exception_arg);
    return value.number_value;
}

/// Returns a string from a JSON value, throwing exception_arg if the type is wrong.
inline fstr_t json_get_string(json_value_t value) {
    if (value.type != JSON_STRING)
        throw(fstr("expected string in JSON"), exception_arg);
    return value.string_value;
}

/// Returns a boolean from a JSON value, throwing exception_arg if the type is wrong.
inline bool json_get_bool(json_value_t value) {
    if (value.type != JSON_BOOL)
        throw(fstr("expected boolean in JSON"), exception_arg);
    return value.bool_value;
}

/// Returns an list (array) from a JSON value, throwing exception_arg if the type is wrong.
inline list(json_value_t)* json_get_array(json_value_t value) {
    if (value.type != JSON_ARRAY)
        throw(fstr("expected array in JSON"), exception_arg);
    return value.array_value;
}

/// Returns a dict (object) from a JSON value, throwing exception_arg if the type is wrong.
inline dict(json_value_t)* json_get_object(json_value_t value) {
    if (value.type != JSON_OBJECT)
        throw(fstr("expected object in JSON"), exception_arg);
    return value.object_value;
}

inline bool json_is_null(json_value_t value) {
    return value.type == JSON_NULL;
}

/// Traverse a chain of JSON properties in a lenient manner, returning a null JSON value
/// if any link in the chain does not exist. Example usage:
///
/// json_tree_t* tree = json_parse("{\"a\": {\"b\": 1}}");
/// json_value_t val = JSON_LREF(tree->value, "a", "b");
/// if (!json_is_null(val)) {
///     do_something(json_get_number(val));
/// }
#define JSON_LREF(value, ...) ({ \
    json_value_t __value = value; \
    fstr_t __path[] = {__VA_ARGS__}; \
    for (int64_t __i = 0; __i < LENGTHOF(__path); __i++) { \
        json_value_t* __next_value = (__value.type == JSON_OBJECT? \
            dict_read(__value.object_value, json_value_t, __path[__i]): 0); \
        __value = (__next_value == 0? json_null_value: *__next_value); \
    } \
    __value; \
})

/// Traverse a chain of JSON properties in a strict manner, throwing an exception if some
/// property traversed does not exist or is null.
#define JSON_REF(value, ...) ({ \
    json_value_t __value = value; \
    fstr_t __path[] = {__VA_ARGS__}; \
    for (int64_t __i = 0; __i < LENGTHOF(__path); __i++) { \
        json_value_t* __next_value = (__value.type == JSON_OBJECT? \
            dict_read(__value.object_value, json_value_t, __path[__i]): 0); \
        __value = (__next_value == 0? json_null_value: *__next_value); \
        if (json_is_null(__value)) \
            json_fail_missing_property(__path[__i]); \
    } \
    __value; \
})

/// Set a property of a JSON object to some value. Example usage:
///
/// json_value_t obj = json_new_object();
/// JSON_SET(obj, "property", json_string_value("value"));
#define JSON_SET(parent, prop, value) ({ \
    assert(parent.type == JSON_OBJECT); \
    dict_replace(parent.object_value, json_value_t, prop, value); \
})

#endif  /* JSON_H */
