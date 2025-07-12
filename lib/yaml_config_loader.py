#!/usr/bin/env python3
import yaml
# -----------------------------------------------------------------------------
#
# Yaml decoder override to disallow duplicate keys
#


class LoaderNoDuplicates(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        # Keep track of seen keys to detect duplicates
        seen_keys = set()
        mapping = {}

        for key_node, value_node in node.value:
            key = self.construct_object(key_node)
            if key in seen_keys:
                raise yaml.YAMLError(f"Duplicate key found: {key}")
            seen_keys.add(key)
            value = self.construct_object(value_node, deep)
            mapping[key] = value

        return mapping


# -----------------------------------------------------------------------------
