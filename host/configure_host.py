#!/usr/bin/env python3
from lib.output_handler import OutputHandler
output = OutputHandler(logfile="logs/configure_host.log")


def run():
    print("test")
    output.output("Success message", type="s")
    output.output("Information message", type="i")
    output.output("Warning message", type="w")
    output.output(
        "Error message, will not exit",
        type="e",
        exit_on_error=False
        )
    output.output("This is a heading", type="h")
