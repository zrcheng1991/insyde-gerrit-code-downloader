#
#  Copyright 2026, Tony Cheng. All rights reserved.
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#

import colorful as cf

cf.use_256_ansi_colors()


class ColoredMessage:
    color_dict = {"NOTE": cf.dimGrey, "WARNING": cf.orange, "ERROR": cf.orangeRed}

    @staticmethod
    def print(message: str) -> None:
        message_level = message.split(":", 2)[0].strip()
        color_code = ColoredMessage.color_dict.get(message_level.upper(), None)
        if color_code is None:
            print(message)
        else:
            print(f"{color_code}{message}{cf.reset}")
