#ifndef JSON_H
#define JSON_H

/// JSON type identifier. Basic types are:
///  o Object
///  o Array
///  o String
///  o Number
///  o Boolean
///  o Null
typedef enum jsontype {
    JSON_NULL = 0,
    JSON_BOOL = 1,
    JSON_NUMBER = 2,
    JSON_STRING = 3,
    JSON_ARRAY = 4,
    JSON_OBJECT = 5,
} jsontype_t;

typedef struct json_value {
    jsontype_t type;
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

#endif  /* JSON_H */
