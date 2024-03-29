# Copyright 2010-2011 Florent Le Coz <louiz@louiz.org>
#
# This file is part of Poezio.
#
# Poezio is free software: you can redistribute it and/or modify
# it under the terms of the zlib license. See the COPYING file.


"""
Starting point of poezio. Launches both the Connection and Gui
"""

import sys
import os
import signal
import logging

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_curses():
    """
    Check if the system ncurses linked with python has unicode capabilities.
    """
    import curses
    if hasattr(curses, 'unget_wch'):
        return True
    print("""\
ERROR: The current python executable is linked with a ncurses version that \
has no unicode capabilities.

This could mean that:
    - python was built on a system where readline is linked against \
libncurses and not libncursesw
    - python was built without ncursesw headers available

Please file a bug for your distribution or fix that on your system and then \
recompile python.
Poezio is currently unable to read your input or draw its interface properly,\
 so it will now exit.""")
    return False


def main():
    """
    Entry point.
    """
    sys.stdout.write("\x1b]0;poezio\x07")
    sys.stdout.flush()
    from poezio import config
    config_path = config.check_create_config_dir()
    config.run_cmdline_args(config_path)
    config.create_global_config()
    config.check_create_log_dir()
    config.check_create_cache_dir()
    config.setup_logging()
    config.post_logging_setup()

    from poezio.config import options

    if options.check_config:
        config.check_config()
        sys.exit(0)

    from poezio import theming
    theming.update_themes_dir()

    from poezio import logger
    logger.create_logger()

    from poezio import roster
    roster.create_roster()

    from poezio import core

    log = logging.getLogger('')

    signal.signal(signal.SIGINT, signal.SIG_IGN) # ignore ctrl-c
    cocore = core.Core()
    signal.signal(signal.SIGUSR1, cocore.sigusr_handler) # reload the config
    signal.signal(signal.SIGHUP, cocore.exit_from_signal)
    signal.signal(signal.SIGTERM, cocore.exit_from_signal)
    if options.debug:
        cocore.debug = True
    cocore.start()

    from slixmpp.exceptions import IqError, IqTimeout
    def swallow_iqerrors(loop, context):
        """Do not log unhandled iq errors and timeouts"""
        if not isinstance(context['exception'], (IqError, IqTimeout)):
            loop.default_exception_handler(context)

    # Warning: asyncio must always be imported after the config. Otherwise
    # the asyncio logger will not follow our configuration and won't write
    # the tracebacks in the correct file, etc
    import asyncio
    loop = asyncio.get_event_loop()
    loop.set_exception_handler(swallow_iqerrors)

    loop.add_reader(sys.stdin, cocore.on_input_readable)
    loop.add_signal_handler(signal.SIGWINCH, cocore.sigwinch_handler)
    cocore.xmpp.start()
    loop.run_forever()
    # We reach this point only when loop.stop() is called
    try:
        cocore.reset_curses()
    except:
        pass
