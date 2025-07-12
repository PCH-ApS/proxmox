#!/usr/bin/env python3

import os


class CheckFiles:
    def __init__(self, file_path):
        self.file_path = file_path
        self.file_exists = False
        self.file_readable = False
        self.file_is_yaml = False
        self.valid = False
        self.errors = []

    def exist(self):
        try:
            if not os.path.isfile(self.file_path):
                self.errors.append(
                    f"Error checking file exists {self.file_path}"
                )
                return False
            self.file_exists = True
            return True

        except Exception as e:
            self.errors.append(
                f"Error checking file {self.file_path}: {str(e)}"
                )

    def readable(self):
        try:
            if not os.access(self.file_path, os.R_OK):
                self.errors.append(
                    f"Error reading file {self.file_path}"
                )
                return False
            self.file_readable = True
            return True

        except Exception as e:
            self.errors.append(
                f"Error checking file {self.file_path}: {str(e)}"
                )

    def yaml_check(self):
        try:
            if not self.file_path.endswith(('.yaml', '.yml')):
                self.errors.append(
                    f"File {self.file_path} is not a YAML file"
                    )
                return False
            self.file_is_yaml = True
            return True

        except Exception as e:
            self.errors.append(
                f"Error checking file {self.file_path}: {str(e)}"
                )

    def check(self):
        self.exist()
        self.readable()
        self.yaml_check()
        self.valid = not self.errors
        return self.valid
