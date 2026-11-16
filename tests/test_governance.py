import unittest
from copy import deepcopy
from src.decision_ledger import assess, canonical_key
from src.drift import diff

SAMPLE={'findings':[{'control':'DIR-001','severity':'High','principal':'test@example.test','role':'Global Administrator',
                     'evidence':{'principal_id':'u1','scope':'/'}}]}

class GovernanceTests(unittest.TestCase):
    def test_open_review_has_stable_fingerprint(self):
        r=assess(SAMPLE,[])
        self.assertEqual(1,r['outstanding'])
        self.assertEqual(canonical_key(SAMPLE['findings'][0]),r['decisions'][0]['finding_id'])
    def test_distinct_attestation_owner_and_approver(self):
        decision={'finding_id':canonical_key(SAMPLE['findings'][0]),'decision':'remediated',
                  'owner':'analyst@example.test','approver':'manager@example.test','ticket':'CHG-101'}
        r=assess(SAMPLE,[decision]);self.assertEqual(0,r['outstanding'])
        self.assertEqual('remediated',r['decisions'][0]['status'])
    def test_self_approval_rejected(self):
        d={'finding_id':canonical_key(SAMPLE['findings'][0]),'decision':'remediated',
           'owner':'alice','approver':'ALICE','ticket':'CHG-101'}
        with self.assertRaises(ValueError): assess(SAMPLE,[d])
    def test_expired_exception_becomes_open(self):
        d={'finding_id':canonical_key(SAMPLE['findings'][0]),'decision':'accepted_exception',
           'owner':'alice','approver':'bob','ticket':'RISK-100','expires_on':'2026-11-01'}
        r=assess(SAMPLE,[d]);self.assertEqual('expired_exception',r['decisions'][0]['status'])
        self.assertEqual(1,r['outstanding'])
    def test_exception_requires_ticket_and_expiry(self):
        d={'finding_id':canonical_key(SAMPLE['findings'][0]),'decision':'accepted_exception',
           'owner':'alice','approver':'bob','ticket':'RISK-100'}
        with self.assertRaises(ValueError):assess(SAMPLE,[d])
    def test_unknown_finding_fails_closed(self):
        with self.assertRaises(ValueError):assess(SAMPLE,[{'finding_id':'made-up','decision':'in_review'}])
    def test_drift_detects_added_directory_role(self):
        a={'directory_role_assignments':[{'principalId':'u1','roleDefinitionId':'role-a','directoryScopeId':'/'}]}
        b=deepcopy(a);b['directory_role_assignments'].append({'principalId':'u2','roleDefinitionId':'role-b','directoryScopeId':'/'})
        r=diff(a,b);self.assertEqual(1,len(r['added_assignments']));self.assertEqual([],r['removed_assignments'])
    def test_drift_ignores_ordering(self):
        a={'directory_role_assignments':[{'principalId':x,'roleDefinitionId':'r','directoryScopeId':'/'} for x in ('u1','u2')]}
        b=deepcopy(a);b['directory_role_assignments'].reverse()
        self.assertEqual([],diff(a,b)['added_assignments'])
        self.assertEqual([],diff(a,b)['removed_assignments'])

if __name__=='__main__':unittest.main()
