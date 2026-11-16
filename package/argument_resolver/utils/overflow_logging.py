"""Scoped logging policy for the overflow pipeline."""
import contextlib
import logging
import os
import sys


class ConsoleFormatter(logging.Formatter):
    """Color the severity label only; never mutate the shared log record."""
    COLORS = {
        logging.DEBUG: '\033[32m',
        logging.INFO: '\033[36m',
        logging.WARNING: '\033[33m',
        logging.ERROR: '\033[31m',
        logging.CRITICAL: '\033[1;31m',
    }

    def __init__(self, stream):
        super().__init__('%(levelname)-8s | %(name)s | %(message)s')
        self.use_color = (
            getattr(stream, 'isatty', lambda: False)()
            and 'NO_COLOR' not in os.environ
            and os.environ.get('TERM') != 'dumb'
        )

    def format(self, record):
        text = super().format(record)
        color = self.COLORS.get(record.levelno) if self.use_color else None
        if color:
            label = f'{record.levelname:<8}'
            return f'{color}{label}\033[0m{text[len(label):]}'
        return text


class AnalysisLogFilter(logging.Filter):
    """Keep application progress, hide library chatter, deduplicate console warnings."""
    LIBRARIES = ('angr', 'cle', 'claripy', 'pyvex', 'archinfo')

    def __init__(self, level, deduplicate=False):
        super().__init__()
        self.level = level
        self.deduplicate = deduplicate
        self.seen = set()
        self.suppressed = 0

    def filter(self, record):
        library = record.name.split('.', 1)[0] in self.LIBRARIES
        threshold = self.level
        if library and self.level != logging.DEBUG:
            threshold = max(threshold, logging.WARNING)
        if record.levelno < threshold:
            return False
        if library and self.deduplicate and self.level != logging.DEBUG and record.levelno >= logging.WARNING:
            key = (record.name, record.levelno, record.getMessage())
            if key in self.seen:
                self.suppressed += 1
                return False
            self.seen.add(key)
        return True


@contextlib.contextmanager
def overflow_logging(level, logfile):
    """Use separate console/file handlers, restoring caller configuration afterwards."""
    root = logging.getLogger()
    previous_level, previous_handlers = root.level, root.handlers[:]
    console = logging.StreamHandler(sys.stderr)
    disk = logging.StreamHandler(logfile)
    console_filter = AnalysisLogFilter(level, deduplicate=True)
    console.addFilter(console_filter)
    disk.addFilter(AnalysisLogFilter(level))
    console.setFormatter(ConsoleFormatter(console.stream))
    disk.setFormatter(logging.Formatter('%(levelname)-8s | %(name)s | %(message)s'))
    root.handlers = [console, disk]
    root.setLevel(level)
    try:
        yield
    finally:
        if console_filter.suppressed:
            message = f'[intoverflow] Suppressed {console_filter.suppressed} repeated library warnings/errors on console; see log file.\n'
            console.stream.write(message)
            logfile.write(message)
        root.handlers = previous_handlers
        root.setLevel(previous_level)
        console.close()
        disk.close()
