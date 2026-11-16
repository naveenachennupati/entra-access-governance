import unittest
from src.review import analyze, make_html
from src.collect import get_pages
from io import BytesIO


class ReadonlyGovernanceTests(unittest.TestCase):
    def base(self):
        return {'source':'Regression fixture',
                'users':[{'id':'u1','displayName':'Alex','userPrincipalName':'alex@example.test','accountEnabled':False,'userType':'Guest'},
                         {'id':'u2','displayName':'Pat','userPrincipalName':'pat@example.test','accountEnabled':True,'userType':'Member','signInActivity':{'lastSignInDateTime':'2026-01-01T00:00:00Z'}}],
                'service_principals':[{'id':'sp1','appId':'a1','displayName':'Provisioner','passwordCredentials':[{'endDateTime':'2026-11-19T00:00:00Z','keyId':'k1'}]}],
                'groups':[{'id':'g1','displayName':'Security team'}],
                'directory_role_definitions':[{'id':'global','displayName':'Global Administrator'}],
                'directory_role_assignments':[{'principalId':'u1','roleDefinitionId':'global','directoryScopeId':'/'},{'principalId':'u2','roleDefinitionId':'global','directoryScopeId':'/'},{'principalId':'sp1','roleDefinitionId':'global','directoryScopeId':'/'}],
                'azure_role_definitions':[{'id':'/subscriptions/s1/providers/Microsoft.Authorization/roleDefinitions/owner','properties':{'roleName':'Owner'}}],
                'azure_role_assignments':[{'id':'assignment1','properties':{'principalId':'sp1','scope':'/subscriptions/s1','roleDefinitionId':'/subscriptions/s1/providers/Microsoft.Authorization/roleDefinitions/owner'}}]}
    def controls(self, data=None):
        return {f['control'] for f in analyze(data or self.base())['findings']}
    def test_disabled_directory_role(self):self.assertIn('DIR-001',self.controls())
    def test_guest_directory_role(self):self.assertIn('DIR-002',self.controls())
    def test_stale_access_only_if_signin_available(self):self.assertIn('DIR-003',self.controls())
    def test_service_principal_high_privilege(self):self.assertIn('DIR-004',self.controls())
    def test_credential_expiry(self):self.assertIn('APP-001',self.controls())
    def test_broad_subscription_role(self):self.assertIn('AZ-001',self.controls())
    def test_app_azure_owner(self):self.assertIn('AZ-002',self.controls())
    def test_unknown_principal_is_review_not_orphan_assertion(self):
        d=self.base();d['azure_role_assignments'][0]['properties']['principalId']='not-collected'
        r=analyze(d)
        f=next(f for f in r['findings'] if f['control']=='AZ-004')
        self.assertEqual('Review',f['severity'])
        self.assertIn('not resolved',f['reason'])
    def test_html_escapes_usernames(self):
        d=self.base();d['users'][0]['userPrincipalName']='<script>alert(1)</script>'
        out=make_html(analyze(d))
        self.assertNotIn('<script>',out)
    def test_no_findings_for_clean_state(self):
        d=self.base();d['users']=[];d['service_principals']=[];d['directory_role_assignments']=[];d['azure_role_assignments']=[]
        self.assertEqual([],analyze(d)['findings'])
    def test_graph_pagination_blocks_cross_domain(self):
        class Reply:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self):return b'{"value":[],"@odata.nextLink":"https://example.com/payload"}'
        def opener(*args,**kwargs):return Reply()
        with self.assertRaises(ValueError):
            get_pages('https://graph.microsoft.com/v1.0/users','dummy','graph.microsoft.com',opener=opener)

if __name__=='__main__':unittest.main()
