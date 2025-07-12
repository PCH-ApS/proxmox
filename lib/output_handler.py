#!/usr/bin/env python3

import os
import sys
import subprocess
from datetime import datetime


class OutputHandler:
    def __init__(self, logfile=None, enable_colors=True):
        self.logfile = logfile
        if self.logfile:
            log_dir = os.path.dirname(self.logfile)
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)
        self.enable_colors = enable_colors

    def _color(self, code):
        return f'\033[{code}m' if self.enable_colors else ''

    def output(self,
               message=None,
               type=None,
               logfile=None,
               exit_on_error=False
               ):
        color_map = {
            's': ('[✓] ', '32'),  # Green
            'i': ('[i] ', '32'),  # Green
            'w': ('[*] ', '33'),  # Yellow
            'e': ('[x] ', '31'),  # Red
            'h': ('', '0')        # Heading
        }

        pre_message, color_code = color_map.get(
            type.lower(),
            ('[?] ', '0')) if type else ('', '0')
        color = self._color(color_code)
        reset = self._color('0')

        if type and type.lower() == 'h':
            if message:
                message = message.upper()
                if len(message) < 78:
                    blanks = 78 - len(message)
                    left_padding = blanks // 2
                    right_padding = blanks - left_padding
                    message = (
                        f"-{' ' * left_padding}{message}{' ' * right_padding}-"
                    )
                else:
                    message = message[:78]
            else:
                message = "-" * 80

        if not message:
            message = "-" * 80

        # Log if needed
        log_path = logfile if logfile else self.logfile
        if log_path:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with open(log_path, 'a') as log_file:
                log_file.write(f"{timestamp} {pre_message}{message}\n")

        # Print to terminal
        print(f"{color}{pre_message}{message}{reset}")

        # Exit if requested
        if type and type.lower() == "e" and exit_on_error:
            print("-" * 80)
            sys.exit(1)

    def notify(self, title, message):
        try:
            subprocess.run(["notify-send", title, message], check=True)
        except Exception as e:
            self.output(f"Notification failed: {e}", type="w")
