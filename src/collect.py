"""Read-only Microsoft Graph and Azure Resource Manager snapshot collector.
Requires an authenticated Azure CLI session; uses only GET operations and no stored tokens.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

ROOT=Path(__file__).resolve().parents[1]
GRAPH='https://graph.microsoft.com/v1.0'
ARM='https://management.azure.com'


def get_token(resource):
    cmd=['az','account','get-access-token','--resource',resource,'--query','accessToken','-o','tsv']
    result=subprocess.run(cmd,capture_output=True,text=True,check=True)
    value=result.stdout.strip()
    if not value: raise RuntimeError('Azure CLI returned empty access token')
    return value


def get_pages(url,token,host,opener=urlopen,max_pages=150):
    """Follow OData pagination with a same-host restriction and stop on HTTP errors."""
    values=[]; visited=set()
    for _ in range(max_pages):
        parsed=urlparse(url)
        if parsed.scheme!='https' or parsed.netloc.lower()!=host:
            raise ValueError('Untrusted cross-host pagination URL blocked')
        if url in visited: raise ValueError('Pagination loop detected')
        visited.add(url)
        req=Request(url,headers={'Authorization':f'Bearer {token}','Accept':'application/json'},method='GET')
        with opener(req,timeout=30) as response:
            data=json.load(response)
        if not isinstance(data.get('value'),list): raise ValueError('Invalid collection payload')
        values.extend(data['value'])
        url=data.get('@odata.nextLink')
        if not url: return values
    raise RuntimeError(f'Exceeded pagination limit: {max_pages}')


def collect(subscription=None,include_signin_activity=False):
    graph_token=get_token('https://graph.microsoft.com/')
    users_select='id,displayName,userPrincipalName,accountEnabled,userType'
    if include_signin_activity:
        users_select+=',signInActivity'
    sources={}
    def graph(path, params=None):
        url=GRAPH+path+('?' + urlencode(params) if params else '')
        rows=get_pages(url,graph_token,'graph.microsoft.com')
        sources[path]=len(rows)
        return rows
    users=graph('/users',{'$select':users_select,'$top':'100'})
    sps=graph('/servicePrincipals',{'$select':'id,displayName,appId,accountEnabled,passwordCredentials','$top':'100'})
    groups=graph('/groups',{'$select':'id,displayName','$top':'100'})
    assignments=graph('/roleManagement/directory/roleAssignments',{'$top':'100'})
    definitions=graph('/roleManagement/directory/roleDefinitions',{'$top':'100'})
    arm_assignments=[]; arm_definitions=[]
    if subscription:
        token=get_token('https://management.azure.com/')
        sub=f'/subscriptions/{subscription}'
        arm_assignments=get_pages(f'{ARM}{sub}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01',token,'management.azure.com')
        arm_definitions=get_pages(f'{ARM}{sub}/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01',token,'management.azure.com')
        sources['azure_role_assignments']=len(arm_assignments)
        sources['azure_role_definitions']=len(arm_definitions)
    return {'source':'Microsoft Graph and Azure Resource Manager read-only GET APIs',
            'collected_utc':datetime.now(timezone.utc).isoformat(),
            'subscription_id':subscription,'sources':sources,'users':users,'service_principals':sps,
            'groups':groups,'directory_role_assignments':assignments,'directory_role_definitions':definitions,
            'azure_role_assignments':arm_assignments,'azure_role_definitions':arm_definitions}


def main():
    p=argparse.ArgumentParser(description='Read-only tenant access evidence collection')
    p.add_argument('--subscription',help='Azure subscription ID; omit to collect directory only')
    p.add_argument('--include-signin-activity',action='store_true',help='Requires suitable Entra licensing/permissions')
    p.add_argument('--out',type=Path,required=True,help='Sensitive output: keep private and outside public GitHub')
    args=p.parse_args()
    data=collect(args.subscription,args.include_signin_activity)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(data,indent=2)+'\n')
    args.out.chmod(0o600)
    print(f'Collected {len(data["users"])} users, {len(data["directory_role_assignments"])} directory assignments, '
          f'{len(data["azure_role_assignments"])} Azure role assignments into private file {args.out}')

if __name__=='__main__': main()
