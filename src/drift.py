"""Diff two authorization snapshots using stable role/scope/principal tuples.
Comparisons show changes to reviewed privilege assignments, not proof of malicious activity.
"""
import argparse
import hashlib
import json
from pathlib import Path

def extract(snapshot):
    assignments=[]
    for item in snapshot.get('directory_role_assignments',[]):
        assignments.append({'platform':'Entra','principal_id':item.get('principalId',''),
                            'role_id':item.get('roleDefinitionId',''),'scope':item.get('directoryScopeId','/')})
    for item in snapshot.get('azure_role_assignments',[]):
        p=item.get('properties',{})
        assignments.append({'platform':'Azure RBAC','principal_id':p.get('principalId',''),
                            'role_id':p.get('roleDefinitionId',''),'scope':p.get('scope','')})
    return {json.dumps(x,sort_keys=True) for x in assignments}

def diff(before,after):
    previous=extract(before);current=extract(after)
    unpack=lambda xs:sorted([json.loads(x) for x in xs],key=lambda x:(x['platform'],x['principal_id'],x['scope'],x['role_id']))
    return {'status':'change review required; membership changes are not categorized as malicious',
            'added_assignments':unpack(current-previous),'removed_assignments':unpack(previous-current),
            'before_count':len(previous),'after_count':len(current),
            'before_sha256':hashlib.sha256(json.dumps(before,sort_keys=True).encode()).hexdigest(),
            'after_sha256':hashlib.sha256(json.dumps(after,sort_keys=True).encode()).hexdigest()}

def main():
    p=argparse.ArgumentParser();p.add_argument('--before',type=Path,required=True);p.add_argument('--after',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();d=diff(json.loads(a.before.read_text()),json.loads(a.after.read_text()))
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(d,indent=2)+'\n')
    print(f"Role changes: {len(d['added_assignments'])} added; {len(d['removed_assignments'])} removed")
if __name__=='__main__':main()
