import unittest
from src.operational_study import simulated_snapshot, evaluate

class GovernanceStudyTests(unittest.TestCase):
    def test_scope(self):
        s=simulated_snapshot();self.assertEqual(len(s['users']),2000)
        self.assertEqual(len(s['directory_role_assignments']),226)
    def test_reproducibility(self):
        self.assertEqual(evaluate()['fixture_sha256'],evaluate()['fixture_sha256'])
    def test_no_auto_certification(self):
        r=evaluate();self.assertLess(r['distinct_first_pass_review_items'],r['control_records_checked'])
        self.assertGreater(r['distinct_first_pass_review_items'],0)
        self.assertTrue(any('not an access certification' in x.lower() for x in r['limitations']))
    def test_no_real_identities(self):
        s=simulated_snapshot()
        self.assertTrue(all(u['userPrincipalName'].endswith('@example.test') for u in s['users']))

if __name__=='__main__': unittest.main()
