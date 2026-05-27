import unittest
from src.parser import parse_log_file

class TestParser(unittest.TestCase):
    def test_parse_log_file(self):
        events = parse_log_file('data/sample_logs.log')
        self.assertGreaterEqual(len(events), 3)
        self.assertEqual(events[0].user, 'admin')

if __name__ == '__main__':
    unittest.main()
