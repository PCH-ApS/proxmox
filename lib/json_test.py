#!/usr/bin/env python3

import json
import sys

def validate_boolean(value, field_name):
    if not isinstance(value, bool):
        print(f"\033[91m[ERROR]           : '{field_name}' must be a boolean (true/false)")
        return False
    return True

def end_output_to_shell():
    print("\033[0m-------------------------------------------")
    print("")

def check_parameters(config, mandatory_keys, optional_keys):
    allowed_keys = set(mandatory_keys.keys()).union(optional_keys.keys())
    errors = []

    try:
        # Check for invalid keys in the JSON
        for key in config.keys():
            if key not in allowed_keys:
                errors.append(f"Invalid key '{key}' found in JSON configuration.")

        # Check for mandatory keys and sub-keys
        for key, sub_key in mandatory_keys.items():
            if key not in config:
                errors.append(f"Missing mandatory key '{key}' in JSON configuration.")
            elif sub_key not in config[key]:
                errors.append(f"Missing mandatory sub-key '{sub_key}' in '{key}' object.")
            elif not validate_boolean(config[key].get("allow_blank", None), f"{key}.allow_blank"):
                errors.append(f"Invalid boolean value for '{key}.allow_blank'.")
            elif not validate_boolean(config[key].get("allow_spaces", None), f"{key}.allow_spaces"):
                errors.append(f"Invalid boolean value for '{key}.allow_spaces'.")

        # Check for 'comment' key in each object, if required
        for key, obj in config.items():
            if "comment" not in obj:
                errors.append(f"'{key}' is missing 'comment' key.")

        # Output all errors if found
        if errors:
            for error in errors:
                print(f"\033[91m[ERROR]           : {error}")
            sys.exit(1)

        print("\033[92m[SUCCESS]         : All parameters are structured correctly")
        end_output_to_shell()

    except Exception as e:
        print(f"\033[91m[ERROR]           : Error while validating the structure in JSON file: {e}")
        sys.exit(1)

def check_values(config, integer_keys=None):
    errors = []

    for key, obj in config.items():
        first_key = next(iter(obj))
        first_value = obj[first_key]

        # Check if allow_blank is false and the value is empty (only for strings)
        if obj.get("allow_blank") is False and isinstance(first_value, str) and first_value == "":
            errors.append(f"'{first_key}' is blank but cannot be blank.")

        # Check if allow_spaces is false and the value contains spaces (only for strings)
        if obj.get("allow_spaces") is False and isinstance(first_value, str) and " " in first_value:
            errors.append(f"'{first_key}' contains spaces but cannot have spaces.")

        # Check if value should be an integer, allowing strings that represent integers
        if integer_keys and key in integer_keys:
            if not isinstance(first_value, int):
                if isinstance(first_value, str):
                    try:
                        # Try to convert the string to an integer
                        int(first_value)
                    except ValueError:
                        errors.append(f"'{first_key}' should be an integer, but found non-integer value: '{first_value}'.")
                else:
                    errors.append(f"'{first_key}' should be an integer, but found type '{type(first_value).__name__}'.")

    # Output any errors found
    if errors:
        for error in errors:
            print(f"\033[91m[ERROR]           : {error}")
        sys.exit(1)

    print("\033[92m[SUCCESS]         : All values are the correct type")
    end_output_to_shell()
