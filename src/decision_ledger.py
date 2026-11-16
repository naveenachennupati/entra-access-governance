"""Two-person access attestations, exception expiry and evidence integrity.

Read-only governance workflow; never calls Microsoft APIs or changes access.
"""
import argparse
from collections import Counter
import csv
from datetime import date
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
STATES={'open','in_review','accepted_exception','remediated','false_positive'}

def canonical_key(finding):
    evidence=finding.get('evidence') or {}
    stable={'control':finding['control'], 'principal_id':evidence.get('principal_id') or evidence.get('app_id') or finding['principal'],
            'scope':evidence.get('scope',''),'role':finding['role'],'assignment_id':evidence.get('assignment_id','')}
    return hashlib.sha256(json.dumps(stable,sort_keys=True).encode()).hexdigest()[:16]

def assess(report, decisions, as_of='2026-11-16'):
    today=date.fromisoformat(as_of)
    keys={canonical_key(f):f for f in report['findings']}
    duplicate_keys=[k for k in set(keys) if sum(canonical_key(f)==k for f in report['findings'])>1]
    if duplicate_keys: raise ValueError('Duplicate finding keys must be resolved before attestation')
    known={}
    for d in decisions:
        key=d.get('finding_id','').strip()
        if key not in keys: raise ValueError(f'Decision references unknown finding: {key}')
        if key in known: raise ValueError('Duplicate reviewer decision')
        state=d.get('decision','open').strip()
        if state not in STATES: raise ValueError(f'Invalid decision: {state}')
        owner=d.get('owner','').strip(); approver=d.get('approver','').strip()
        ticket=d.get('ticket','').strip(); expire=d.get('expires_on','').strip()
        if state in {'remediated','false_positive','accepted_exception'}:
            if not owner or not approver or owner.casefold()==approver.casefold():
                raise ValueError('Closed/exception decisions require different owner and approver')
            if not ticket: raise ValueError('Closed/exception decisions require evidence ticket')
        if state=='accepted_exception':
            if not expire: raise ValueError('Exception must have expiration')
            if date.fromisoformat(expire)<today: state='expired_exception'
        known[key]={'status':state,'owner':owner,'approver':approver,'ticket':ticket,'expires_on':expire}
    output=[]
    for key,f in keys.items():
        output.append({'finding_id':key,'control':f['control'],'severity':f['severity'],
                       'principal':f['principal'],'role':f['role'],
                       **known.get(key,{'status':'open','owner':'','approver':'','ticket':'','expires_on':''})})
    output.sort(key=lambda x:(x['severity'],x['control'],x['principal']))
    return {'as_of':as_of,'method':'two-person attestation with expiring exceptions; no system changes',
            'source_review_sha256':hashlib.sha256(json.dumps(report,sort_keys=True).encode()).hexdigest(),
            'counts':dict(Counter(x['status'] for x in output)),'decisions':output,
            'outstanding':sum(x['status'] in ('open','in_review','expired_exception') for x in output)}

def write_evidence(result,out):
    out.mkdir(parents=True,exist_ok=True)
    (out/'attestation.json').write_text(json.dumps(result,indent=2)+'\n')
    columns=['finding_id','control','severity','principal','role','status','owner','approver','ticket','expires_on']
    with (out/'attestation.csv').open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=columns,extrasaction='ignore');writer.writeheader();writer.writerows(result['decisions'])

def main():
    p=argparse.ArgumentParser(description='Evidence-backed read-only entitlement attestation')
    p.add_argument('--review',type=Path,required=True)
    p.add_argument('--decisions',type=Path,help='Optional reviewer decisions CSV')
    p.add_argument('--as-of',default=date.today().isoformat());p.add_argument('--out',type=Path,default=ROOT/'reports')
    args=p.parse_args()
    report=json.loads(args.review.read_text())
    if args.decisions:
        with args.decisions.open(newline='') as file: decisions=list(csv.DictReader(file))
    else: decisions=[]
    result=assess(report,decisions,args.as_of);write_evidence(result,args.out)
    print(f"{len(result['decisions'])} findings; {result['outstanding']} awaiting decisions (including expired exceptions)")

if __name__=='__main__': main()
