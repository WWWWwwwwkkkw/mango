import contextlib
import io
import logging
import unittest
from unittest.mock import patch

from argument_resolver.utils.overflow_logging import overflow_logging


class OverflowLoggingTests(unittest.TestCase):
    def test_color_only_on_terminal_and_never_in_file(self):
        class Terminal(io.StringIO):
            def isatty(self):
                return True

        for no_color in (False, True):
            console, disk = Terminal(), io.StringIO()
            env = {'TERM': 'xterm-256color'}
            if no_color:
                env['NO_COLOR'] = '1'
            with patch.dict('os.environ', env, clear=True), contextlib.redirect_stderr(console), overflow_logging(logging.INFO, disk):
                logging.getLogger('argument_resolver.test_logging').info('progress')
                logging.getLogger('argument_resolver.test_logging').error('failure')
            self.assertEqual('\033[36mINFO' in console.getvalue(), not no_color)
            self.assertEqual('\033[31mERROR' in console.getvalue(), not no_color)
            self.assertNotIn('\033[', disk.getvalue())

    def test_default_keeps_progress_and_errors_without_library_spam(self):
        console, disk = io.StringIO(), io.StringIO()
        root = logging.getLogger()
        handlers, level = root.handlers[:], root.level
        with contextlib.redirect_stderr(console), overflow_logging(logging.INFO, disk):
            logging.getLogger('angr.test_logging').info('internal merge')
            logging.getLogger('argument_resolver.test_logging').info('Phase STEP')
            for _ in range(3):
                logging.getLogger('angr.test_logging').warning('overlap warning')
            logging.getLogger('angr.test_logging').error('distinct error')
        self.assertNotIn('internal merge', console.getvalue())
        self.assertNotIn('\033[', console.getvalue())
        self.assertIn('Phase STEP', console.getvalue())
        self.assertEqual(console.getvalue().count('overlap warning'), 1)
        self.assertEqual(disk.getvalue().count('overlap warning'), 3)
        self.assertIn('distinct error', console.getvalue())
        self.assertEqual(root.handlers, handlers)
        self.assertEqual(root.level, level)

    def test_debug_exposes_internal_messages_and_warning_filters_progress(self):
        for level in (logging.DEBUG, logging.WARNING):
            console = io.StringIO()
            with contextlib.redirect_stderr(console), overflow_logging(level, io.StringIO()):
                logging.getLogger('angr.test_logging').debug('internal details')
                logging.getLogger('argument_resolver.test_logging').info('progress')
                logging.getLogger('angr.test_logging').warning('warning')
            self.assertEqual('internal details' in console.getvalue(), level == logging.DEBUG)
            self.assertEqual('progress' in console.getvalue(), level == logging.DEBUG)
            self.assertIn('warning', console.getvalue())


if __name__ == '__main__':
    unittest.main()
