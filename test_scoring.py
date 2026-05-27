import unittest
from src.scoring import score_alert

class TestScoring(unittest.TestCase):
    def test_score_alert(self):
        score, severity = score_alert(50, 'admin', 5, {'reputation': 'malicious', 'confidence': 95}, correlation_boost=10)
        self.assertGreaterEqual(score, 80)
        self.assertIn(severity, {'High', 'Critical'})

if __name__ == '__main__':
    unittest.main()
