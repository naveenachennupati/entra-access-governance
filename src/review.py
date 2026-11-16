"""Evidence-based, non-destructive identity & Azure RBAC access review."""
import argparse
from collections import Counter
from datetime import datetime,timezone
from html import escape
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SEVERITIES={'Critical':0,'High':1,'Medium':2,'Review':3}


def dt(value):
    if not value:return None
    try:return datetime.fromisoformat(value.replace('Z','+00:00'))
    except (ValueError,TypeError):return None


def analyze(snapshot, reference_date='2026-11-16', stale_days=90):
    now=datetime.fromisoformat(reference_date+'T00:00:00+00:00')
    users={x['id']:x for x in snapshot.get('users',[]) if x.get('id')}
    sps={x['id']:x for x in snapshot.get('service_principals',[]) if x.get('id')}
    groups={x['id']:x for x in snapshot.get('groups',[]) if x.get('id')}
    defs={x['id']:x['displayName'] for x in snapshot.get('directory_role_definitions',[]) if x.get('id')}
    az_defs={x['id'].split('/')[-1].lower():x.get('properties',{}).get('roleName','') for x in snapshot.get('azure_role_definitions',[]) if x.get('id')}
    findings=[]
    def add(code,severity,principal,role,reason,action,evidence):
        findings.append({'control':code,'severity':severity,'principal':principal,'role':role,
                         'evidence':evidence,'reason':reason,'review_action':action,
                         'source':'access review evidence'})
    for a in snapshot.get('directory_role_assignments',[]):
        p_id=a.get('principalId','')
        role=defs.get(a.get('roleDefinitionId'), f"Unresolved role ID {a.get('roleDefinitionId','')}")
        user=users.get(p_id)
        sp=sps.get(p_id)
        principal=(user or sp or groups.get(p_id) or {}).get('userPrincipalName') or (user or sp or groups.get(p_id) or {}).get('displayName',p_id)
        ev={'principal_id':p_id,'role_definition_id':a.get('roleDefinitionId'),'scope':a.get('directoryScopeId','/')}
        if user and not user.get('accountEnabled',True):
            add('DIR-001','High',principal,role,'Disabled identity retains a directory role','Confirm identity status and revoke unneeded assignment after approval',ev)
        if user and user.get('userType','').lower()=='guest':
            add('DIR-002','High',principal,role,'External guest holds a directory role','Confirm sponsorship, scope and business justification',ev)
        signin=(user or {}).get('signInActivity') or {}
        last=dt(signin.get('lastSuccessfulSignInDateTime') or signin.get('lastSignInDateTime'))
        if user and last and (now-last).days>=stale_days:
            add('DIR-003','Medium',principal,role,f'No recorded sign-in for {(now-last).days} days (data availability dependent)',
                'Verify service usage and access owner before removal',dict(ev,last_signin=last.isoformat()))
        if sp and role.lower() in ('global administrator','privileged role administrator'):
            add('DIR-004','High',principal,role,'Service principal has a highly privileged directory role',
                'Validate application owner, privilege rationale and identity protections',ev)
    for sp in snapshot.get('service_principals',[]):
        name=sp.get('displayName',sp.get('id','unknown'))
        for credential in sp.get('passwordCredentials',[]) or []:
            expires=dt(credential.get('endDateTime'))
            if not expires: continue
            days=(expires-now).days
            if days<=30:
                add('APP-001','High' if days<0 else 'Medium',name,'Application credential',
                    'Credential expired' if days<0 else f'Credential expires in {days} days',
                    'Coordinate approved rotation using a secure secret store',
                    {'app_id':sp.get('appId'),'expires_utc':expires.isoformat(),'key_id':credential.get('keyId')})
    for a in snapshot.get('azure_role_assignments',[]):
        prop=a.get('properties',{})
        rid=prop.get('roleDefinitionId','').split('/')[-1].lower()
        role=az_defs.get(rid,'Unresolved')
        pid=prop.get('principalId','')
        principal=(users.get(pid) or sps.get(pid) or groups.get(pid) or {}).get('userPrincipalName') or (users.get(pid) or sps.get(pid) or groups.get(pid) or {}).get('displayName',pid)
        scope=prop.get('scope','')
        evidence={'assignment_id':a.get('id'),'principal_id':pid,'scope':scope,'role_name':role}
        if role in ('Owner','User Access Administrator') and scope.count('/') <= 2:
            add('AZ-001','Medium',principal,role,'Broad subscription-scope permission warrants business-owner attestation',
                'Review whether resource-group scope or a narrower role satisfies the need',evidence)
        if pid in sps and role=='Owner':
            add('AZ-002','High',principal,role,'Application identity has Azure Owner role',
                'Confirm workload ownership and eliminate excess privileges when feasible',evidence)
        if pid in users and users[pid].get('userType','').lower()=='guest' and role in ('Owner','Contributor','User Access Administrator'):
            add('AZ-003','High',principal,role,'External guest has privileged Azure role',
                'Confirm guest sponsorship, scope and access-review decision',evidence)
        if pid and pid not in users and pid not in sps and pid not in groups:
            add('AZ-004','Review',pid,role,'Principal not resolved by the collected Graph directory snapshot (may be out of scope)',
                'Resolve principal in directory before classifying as orphaned',evidence)
    findings.sort(key=lambda f:(SEVERITIES[f['severity']],f['control'],f['principal']))
    return {'as_of':reference_date,'source':snapshot.get('source','unspecified'),
            'record_counts':{'users':len(users),'applications':len(sps),'directory_role_assignments':len(snapshot.get('directory_role_assignments',[])),
                             'azure_role_assignments':len(snapshot.get('azure_role_assignments',[]))},
            'severity_counts':dict(Counter(f['severity'] for f in findings)), 'findings':findings,
            'interpretation':'Reviewer queue; findings are prompts for owner validation, not proof of compromise.'}


def make_html(result):
    findings=result['findings']
    cards=''.join(f'<div class="metric"><span>{escape(str(result["severity_counts"].get(s,0)))}</span><small>{s}</small></div>' for s in ('High','Medium','Review'))
    rows='\n'.join('<tr><td><strong>'+escape(f['control'])+'</strong></td><td><span class="pill '+f['severity'].lower()+'">'+f['severity']+'</span></td><td>'+escape(str(f['principal']))+'</td><td>'+escape(f['role'])+'</td><td>'+escape(f['reason'])+'</td><td>'+escape(f['review_action'])+'</td></tr>' for f in findings)
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Access governance review</title><style>body{{font-family:Inter,Arial,sans-serif;background:#0e1728;color:#e9eff8;margin:0}}main{{max-width:1180px;margin:auto;padding:42px 28px}}.eyebrow{{color:#60e1ce;letter-spacing:.16em;text-transform:uppercase;font-size:12px}}h1{{font-size:38px;letter-spacing:-.04em}}p{{color:#b8c9d8;line-height:1.6}}.grid{{display:flex;gap:12px;flex-wrap:wrap;margin:26px 0}}.metric{{background:#172438;border:1px solid #2b4258;padding:20px;border-radius:12px;min-width:135px}}.metric span{{font-size:30px;display:block}}small{{color:#adc4d4}}table{{background:#172438;width:100%;border-collapse:collapse;border-radius:12px;overflow:hidden}}th,td{{border-bottom:1px solid #2b4258;text-align:left;padding:13px 10px;font-size:13px;vertical-align:top}}th{{color:#66d8cd}}.scroll{{overflow-x:auto}}.pill{{padding:5px 9px;border-radius:20px;background:#435062}}.high{{background:#6c343d}}.medium{{background:#664c2b}}footer{{margin-top:25px;color:#98adbd}}</style></head><body><main><div class="eyebrow">Identity / Access Governance</div><h1>Privilege review queue</h1><p>As of {escape(result['as_of'])} · Source: {escape(result['source'])}. Review findings against business owners before remediation.</p><div class="grid">{cards}</div><div class="scroll"><table><thead><tr><th>Control</th><th>Priority</th><th>Principal</th><th>Role</th><th>Evidence-based rationale</th><th>Owner review action</th></tr></thead><tbody>{rows}</tbody></table></div><footer>{escape(result['interpretation'])}</footer></main></body></html>'''


def main():
    p=argparse.ArgumentParser(description='Review Graph/ARM identity snapshot without making any changes')
    p.add_argument('--input',type=Path,required=True)
    p.add_argument('--out',type=Path,default=ROOT/'reports')
    p.add_argument('--as-of',default=datetime.now(timezone.utc).date().isoformat())
    args=p.parse_args()
    data=json.loads(args.input.read_text())
    result=analyze(data,args.as_of)
    args.out.mkdir(parents=True,exist_ok=True)
    (args.out/'review.json').write_text(json.dumps(result,indent=2)+'\n')
    (args.out/'review.html').write_text(make_html(result))
    print(f'Reviewed {result["record_counts"]}; {len(result["findings"])} finding(s) requiring owner verification.')

if __name__=='__main__':main()
