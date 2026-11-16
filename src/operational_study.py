"""Capacity / exception-queue study over a generated, non-production Entra/RBAC snapshot.

Illustrates how a read-only reviewer queue supports targeted first-pass escalation;
it does not replace a complete access certification, Microsoft Graph live data,
or demonstrate a real organization's remediation results.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from html import escape
from .review import analyze

BASE=Path(__file__).resolve().parents[1]

def simulated_snapshot():
    users=[]
    for i in range(2000):
        record={'id':f'u-{i:05d}','displayName':f'Identity {i:05d}',
                'userPrincipalName':f'identity-{i:05d}@example.test',
                'accountEnabled':i not in range(0,18),
                'userType':'Guest' if 18<=i<37 else 'Member',
                'signInActivity':{'lastSignInDateTime':'2026-06-01T12:00:00Z' if 37<=i<80 else '2026-11-12T12:00:00Z'}}
        users.append(record)
    sps=[]
    for i in range(30):
        sps.append({'id':f'sp-{i:03d}','displayName':f'Integration {i:03d}',
                    'appId':f'00000000-0000-0000-0000-{i:012d}',
                    'passwordCredentials':[{'keyId':f'key-{i}',
                      'endDateTime':'2026-11-22T00:00:00Z' if i<10 else '2027-07-01T00:00:00Z'}]})
    directory=[{'principalId':f'u-{i:05d}','roleDefinitionId':'role-global','directoryScopeId':'/'} for i in range(220)]
    directory += [{'principalId':f'sp-{i:03d}','roleDefinitionId':'role-global','directoryScopeId':'/'} for i in range(6)]
    az=[]
    for i in range(120):
        if i<8: pid=f'u-{18+i:05d}'
        elif i<13: pid=f'sp-{i-8:03d}'
        else: pid=f'u-{200+i:05d}'
        role='owner' if i<42 else 'contributor'
        scope='/subscriptions/demo' if i<42 else f'/subscriptions/demo/resourceGroups/sandbox-{i%10}'
        az.append({'id':f'az-assignment-{i:03d}','properties':{'principalId':pid,'scope':scope,
                 'roleDefinitionId':f'/subscriptions/demo/providers/Microsoft.Authorization/roleDefinitions/{role}'}})
    return {'source':'Generated 2,000-user capacity fixture; NOT Microsoft Graph data',
       'users':users,'service_principals':sps,'groups':[],
       'directory_role_definitions':[{'id':'role-global','displayName':'Global Administrator'}],
       'directory_role_assignments':directory,
       'azure_role_definitions':[{'id':f'/subscriptions/demo/providers/Microsoft.Authorization/roleDefinitions/{name}',
               'properties':{'roleName':display}} for name,display in [('owner','Owner'),('contributor','Contributor')]],
       'azure_role_assignments':az}

def evaluate():
    snapshot=simulated_snapshot();r=analyze(snapshot,'2026-11-16')
    role_population=len(snapshot['directory_role_assignments'])+len(snapshot['azure_role_assignments'])
    credential_population=sum(len(sp['passwordCredentials']) for sp in snapshot['service_principals'])
    actionable=set()
    for f in r['findings']:
        if f['control']=='APP-001':
            actionable.add(('app-credential',f['evidence'].get('app_id'),f['evidence'].get('key_id')))
        elif f['control'].startswith('DIR-'):
            e=f['evidence'];actionable.add(('directory',e['principal_id'],e['role_definition_id'],e['scope']))
        elif f['control'].startswith('AZ-'):
            actionable.add(('azure',f['evidence']['assignment_id']))
    denominator=role_population+credential_population
    unique_principals=len({f['principal'] for f in r['findings']})
    evidence=json.dumps(snapshot,sort_keys=True,separators=(',',':')).encode()
    return {'study':'Identity governance first-pass exception queue - generated scale exercise',
            'evidence_level':'Deterministic fictional identity/role fixture; not an actual Entra tenant review',
            'users':len(snapshot['users']),'service_principals':len(snapshot['service_principals']),
            'role_assignments':role_population,'application_credentials':credential_population,
            'control_records_checked':denominator,
            'raw_control_findings':len(r['findings']),'distinct_first_pass_review_items':len(actionable),
            'not_flagged_in_initial_policy_scan':denominator-len(actionable),
            'initial_queue_share_pct':round(100*len(actionable)/denominator,1),
            'distinct_principals_to_contact':unique_principals,
            'findings_by_control':dict(Counter(f['control'] for f in r['findings'])),
            'fixture_sha256':hashlib.sha256(evidence).hexdigest(),
            'source_completeness':'Synthetic data has full fixture fields; Graph production pagination, consent, and licensing not tested',
            'limitations':['This is an exception-prioritization queue, not an access certification; all privileged access requires periodic owner review.',
                    'Findings are possible policy exceptions, not confirmed improper access or completed remediations.',
                    'Simulated user count and queue composition are design parameters; no enterprise performance result is implied.',
                    'Microsoft Graph/ARM collectors require independently authorized tenant integration tests.']}

def write(report, out):
    out.mkdir(parents=True,exist_ok=True)
    (out/'operational-study.json').write_text(json.dumps(report,indent=2)+'\n')
    rows=''.join(f'<tr><td>{escape(code)}</td><td>{n}</td></tr>' for code,n in sorted(report['findings_by_control'].items()))
    limits=''.join('<li>'+escape(s)+'</li>' for s in report['limitations'])
    html=f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Access governance study</title><style>body{{background:#0c1728;color:#edf6fa;font:15px/1.65 Arial,sans-serif;margin:0}}main{{max-width:940px;margin:50px auto;padding:0 24px}}h1{{font-size:36px}}.over{{color:#65ddc3;text-transform:uppercase;letter-spacing:2px}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin:22px 0}}.card{{background:#1a2c41;padding:18px;border-radius:10px}}.card b{{display:block;font-size:32px;color:#85e7d3}}.card span{{font-size:13px;color:#c2d0da}}table{{width:100%;border-collapse:collapse;background:#182b3f}}td,th{{text-align:left;padding:10px;border-bottom:1px solid #395062}}p,li{{color:#c3d1dc}}</style></head><body><main><p class="over">Identity governance / modeled capacity study</p><h1>From entitlement inventory to reviewer decisions</h1><p>Generated, fictional 2,000-user access-review snapshot. An explainable policy scan identifies a focused first-pass exception queue; nonflagged access is NOT certified as safe.</p><div class="cards"><div class="card"><b>{report['users']:,}</b><span>fictional users</span></div><div class="card"><b>{report['control_records_checked']}</b><span>role and credential records checked</span></div><div class="card"><b>{report['distinct_first_pass_review_items']}</b><span>distinct items requiring priority review</span></div><div class="card"><b>{report['initial_queue_share_pct']}%</b><span>first-pass exception share</span></div></div><h2>Control findings</h2><table><tr><th>Control</th><th>Findings</th></tr>{rows}</table><p>Raw findings may be multiple controls on one assignment. Deduplicated review items = {report['distinct_first_pass_review_items']}; distinct affected principals = {report['distinct_principals_to_contact']}.</p><h2>What this does not prove</h2><ul>{limits}</ul><p>Fixture fingerprint: <code>{report['fixture_sha256']}</code>.</p></main></body></html>'''
    (out/'operational-study.html').write_text(html)

def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,default=BASE/'reports');a=p.parse_args()
    data=evaluate();write(data,a.out)
    print(f"Synthetic scope: {data['users']:,} users, {data['control_records_checked']} role/credential records, {data['distinct_first_pass_review_items']} first-pass reviewer items")

if __name__=='__main__':main()
