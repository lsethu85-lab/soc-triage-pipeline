import unittest
from src.main import build_alerts

class TestPipeline(unittest.TestCase):
    def test_build_alerts(self):
        alerts = build_alerts('data/sample_logs.log', 'data/ioc_reputation.json', 'rules/detection_rules.json', 'data/github_events.json')
        self.assertGreaterEqual(len(alerts), 3)
        titles = ' | '.join(a['title'] for a in alerts)
        self.assertTrue('Bruteforce' in titles or 'Multiple failed logins' in titles)

if __name__ == '__main__':
    unittest.main()
