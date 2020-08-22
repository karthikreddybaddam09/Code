#!/usr/bin/python
from __future__ import print_function

import json
import requests
import time, datetime
import sys, os.path
sys.path.append(os.path.abspath('../'))
import availableScans as scan
import availableScans01 as scan01
import availableScans02 as scan02 
import availableScans03 as scan03


ENVIRONMENT = 'prod'
SKIP_DEACTIVE = True

# These will be loaded in api_key.py, if available
MY_ACCOUNTS={}
MY_TENANTS={}
MY_ACCOUNT_LIST=[]

def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""

    if isinstance(obj, datetime.datetime):
        serial = obj.isoformat()
        return serial
    raise TypeError ("Type not serializable")  

def cvtime(sec):
    m, s = divmod(sec, 60)
    h, m = divmod(m, 60)
    d, h = divmod(h, 24)
    return (d, h, m, s)
    # return "%d days %d:%02d:%02d" % (d, h, m, s)

def get_param_interactive(p_prompt, p_default=None, p_allowed=[],p_min=None,p_max=None):
	p_done=False
	p_prompt_string = p_prompt
	if (p_default):
		p_prompt_string = p_prompt_string + ' ['+p_default+']'
	p_prompt_string = p_prompt_string+":"
	while not p_done:
		user_input = raw_input(p_prompt_string)
		if (user_input == ''):
			user_input=p_default
	#Checks
		p_done = True

		if (p_allowed):
			if (user_input not in p_allowed):
				print ("Allowed values are: ", end=None)
				print(p_allowed)
				p_done=False
		if p_min:
			if len(user_input) < p_min:
				print ('Minimum Length is ',end=None)
				print (p_min)
				p_done=False
		if p_max:
			if len(user_input) > p_max:
				print ('Maximum Length is ',end=None)
				print (p_max)
				p_done=False
	return user_input

def find_regions(acct) :
    import boto3
    from botocore.client import ClientError
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    
                    )
    else:
        my_session = boto3.Session()
    regions = []
    my_client = my_session.client('ec2')
    try:
        r_list = my_client.describe_regions()
        for i in r_list['Regions'] :
            regions.append(i['RegionName'])
    except ClientError as e:
        print("%s for Tenant %s and Account %s" % (e.response['Error']['Code'], a['tenantId'], a['accountId']))
    return regions


my_mode = get_param_interactive("Enter operation mode [key/local]", 'local', ['key', 'local'])
if my_mode == 'local':
    KEYMODE=False
else:
    KEYMODE = True

if KEYMODE:
    try:
        import api_key
        APIHEADER={"Authorization" : "API "+api_key.APIKEY[ENVIRONMENT]}
        MY_ACCOUNTS=api_key.MY_ACCOUNTS
        MY_TENANTS=api_key.MY_TENANTS
        MY_ACCOUNT_LIST = api_key.MY_ACCOUNT_LIST
    except ImportError:
        print('Cannot import api_key')
        exit()
    except KeyError:
        print('API key not found for environment "%s"' % ENVIRONMENT)
        exit()

DEBUG = False
DEBUG_URL=False
DEBUG_HEADERS=False

if DEBUG:
    import textwrap
    import pprint

if ENVIRONMENT == 'prod':
    URL ="https://api.cloudplatform.accenture.com"
else:
    URL ="https://api."+ENVIRONMENT+".cloudplatform.accenture.com"

# ACCOUNT_FILE = '../accounts.json'
ACCOUNT_FILE = '/Users/thomas.w.myers/Documents/git repositories/cloudcontrols/accounts.json'
# DEACTIVE_FILE = '../deactivated_accounts.txt'
DEACTIVE_FILE = '/Users/thomas.w.myers/Documents/git repositories/cloudcontrols/deactivated_accounts.txt'

def outfile(name):
    nowstr=datetime.datetime.utcnow().isoformat()
    myfile="%s-%s.csv" % (name, nowstr[:-7].replace(':', '_'))
    # print(myfile)
    return (myfile, open(myfile, "w+"))

def check_error(r, operationData, postData, quit=True, url=None, suppress=False):
    if DEBUG:
        wrapper = textwrap.TextWrapper(initial_indent="   ", subsequent_indent="   ")
        print("====DEBUG====")
    if DEBUG or DEBUG_URL:
        print("URL <",url,">")
    if DEBUG:
        if DEBUG_HEADERS:
            print("Headers")
            print(wrapper.fill(pprint.pformat(r.headers, width=120)))
        try:
            if r.json():
                print("JSON")
                print(r.json())
            else:
                print("Text")
                print(wrapper.fill(r.text))
                # print('   None')
        except:
            print("  Error in JSON")
            print("  Text is")
            print(wrapper.fill(r.text))
        print("record")
        print('  ',r)
        print("--------")
        print("Request body was")
        print(r.request.body)
        if DEBUG_HEADERS:
            print("--------")
            print("Request Headers")
            print(wrapper.fill(pprint.pformat(r.request.headers, width=120)))
        print("====/DEBUG====")
    if not r.ok:
        print("====NOT OK====")
        print("Status code",r.status_code,"was received while",operationData["CurrentEvent"])
        LOGFILE.write("Status code %s was received while %s for Tenant %s and %s\n" % (r.status_code, operationData['CurrentEvent'], operationData['tenant'], operationData['resource']))
        print("Tenant :",end=" ")
        if operationData["tenant"]:
            print (operationData["tenant"])
        else:
            print("N/A")
        print("Resource :",end=" ")
        if operationData["resource"]:
            print (operationData["resource"])
        else:
            print("N/A") 
        print("Attributes :",end=" ")
        if operationData["attributes"]:
            print (operationData["attributes"])
        else:
            print("N/A")

        print("Response:", end=" ")
        try:
            print(r.json()["message"])
        except:
            print(r.text)
        print("====/NOT OK====")
        if quit:
            sys.exit()
        else:
            return True
        
    
    try:
        if not suppress:
            if not r.json():
                print("No JSON in response.")
                print("Status code",r.status_code,"was received while",operationData["CurrentEvent"])
                if quit:
                    sys.exit()
                else:
                    return True
    except:
        if not suppress:
            print('Bad JSON in response')
            print("Status code",r.status_code,"was received while",operationData["CurrentEvent"])
            if quit:
                sys.exit()
            else:
                return True
    if DEBUG:
        print("====Raw Response (Debug)====")
        print(r)
        print("====/Raw Response (DEBUG)====")
    return False

def errfmt(act, acct, attr=None):
    od = {}
    od["CurrentEvent"] = act
    od["tenant"] = acct['tenantId']
    od['resource'] = "Account %s" % acct['accountId']
    if attr:
        od['attributes'] = attr
    else:
        od['attributes'] = None
    return od

def get_credential(rec):
    my_url = '%s/account/tenants/%s/accounts/%s' % (URL, rec['tenantId'], rec['accountId'])
    response = requests.get(my_url, headers=APIHEADER)
    key=(None,None)
    if check_error(response, errfmt("getting account secret", rec), None, quit=False, url=my_url):
        LOGFILE.write('Error getting credential for tenant %s and account %s\n' % (rec['tenantId'], rec['accountId']))
        return key
    resp=response.json()
    if 'secretId' not in resp.keys():
        LOGFILE.write('Bad Response for account secret: %s' % json.dumps(resp))
        return key
    mySid = resp['secretId']
    my_url = '%s/secret/tenants/%s/secrets/%s' % (URL, rec['tenantId'], mySid)
    response=requests.get(my_url, headers=APIHEADER)
    if check_error(response, errfmt("getting secret", rec), None, quit=False, url=my_url):
        LOGFILE.write('Error getting secret for tenannt %s and secret ID %s\n' % (rec['tenantId'], mySid))
        return key
    resp=response.json()
    if 'secret' not in resp.keys():
        LOGFILE.write('No secret in response for %s\n' % json.dumps(resp))
    else:
        if 'accessKey' not in resp['secret'].keys() or 'secretKey' not in resp['secret'].keys():
            LOGFILE.write('Bad Response for secret: %s\n' % json.dumps(resp))
        else:
            key=(resp['secret']['accessKey'], resp['secret']['secretKey'])
    return key

def load_accounts(filename, LOGFILE, deactivefilename=None):
    if SKIP_DEACTIVE:
        if deactivefilename:
            with open(deactivefilename, 'r') as dfh:
                deactiveAccounts = dfh.read().splitlines()
            LOGFILE.write("Loaded %s deactivated accounts\n" % len(deactiveAccounts))
            da_skipped=0
    with open(filename, 'r') as fh:
        acctFile = fh.read()
    data = json.loads(acctFile)
    tenants={}
    providerCounts={}
    for rec in data:
        if rec.get('provider','None') not in providerCounts:
            providerCounts[rec.get('provider', 'None')]=1
        else:
            providerCounts[rec.get('provider', 'None')]+=1
        if rec.get('provider') == 'aws':
            my_account = rec.get('providerAccountId')
            if SKIP_DEACTIVE:
                if my_account in deactiveAccounts:
                    # LOGFILE.write('Skipping deactivated account %s\n' % my_account)
                    da_skipped+=1
                    continue
            my_tenant = rec.get('tenantId')
            if my_account in tenants.keys():
                if tenants[my_account] == my_tenant:
                    continue
                else:
                    LOGFILE.write('Account ID %s for tenant %s also found for tenant %s\n' % (my_account, tenants[my_account], rec['tenantId']))
                    continue
            tenants[my_account]=my_tenant
    LOGFILE.write('Loaded %s accounts from %s records\n' % (len(tenants), len(data)))
    if SKIP_DEACTIVE:
        LOGFILE.write("Skipped %s deactivated accounts\n" % da_skipped)
    for ac in providerCounts:
        LOGFILE.write('%15s %i\n' % (ac, providerCounts[ac]))
    my_accounts=[]
    for a in tenants.keys():
        my_accounts.append(
            {
                'accountId' : a,
                'tenantId'  : tenants[a]
            }
        )
    return (my_accounts, deactiveAccounts)

def find_tenant(aid, accounts):
    miss={}
    for a in accounts:
        if a['accountId']==aid:
            return a['tenantId']
        else:
            miss[a['accountId']]=a['tenantId']
    return "Tenant not found"

def find_accounts(tid, accounts):
    result = []
    for a in accounts:
        if a['tenantId']==tid:
            result.append({
                "accountId" : a['accountId'],
                "tenantId"  : a['tenantId']   # == tid
            }
            )
    return result

def mergeScans():
    my_scans = scan.AWS_SCANS
    my_scans.update(scan01.AWS_SCANS)
    my_scans.update(scan02.AWS_SCANS)
    my_scans.update(scan03.AWS_SCANS)
    return my_scans

def mergeScansType():
    my_scans_type = scan.AWS_SCANS_TYPE
    my_scans_type.update(scan01.AWS_SCANS_TYPE)
    my_scans_type.update(scan02.AWS_SCANS_TYPE)
    my_scans_type.update(scan03.AWS_SCANS_TYPE)
    return my_scans_type

def mergeScansParams():
    my_parameter_scans = scan.PARAMETER_SCANS
    # my_parameter_scans.update(scan01.PARAMETER_SCANS)
    # my_parameter_scans.update(scan02.PARAMETER_SCANS)
    # my_parameter_scans.update(scan03.PARAMETER_SCANS)
    return my_parameter_scans


if not KEYMODE:
    myAccessKey = get_param_interactive("Enter Access Key (or return for environment default")
    if myAccessKey:
        mySecretKey = get_param_interactive("Enter Secret Key")

my_account = 'ALL'
my_tenant = 'ALL'
if KEYMODE:
    my_param = get_param_interactive("Specify Tenant/Account [t/a]", 'n', ['t', 'a', 'n'])
    if my_param == 'a':
        my_account = get_param_interactive("AccountId [ALL/[NOT]LIST/number]", "ALL")
    if my_param == 't':
        my_tenant = get_param_interactive("TenantId [ALL/number]", "ALL")

print ("Available Scans")
allScans = mergeScans()
allScanstype = mergeScansType()
allScansParams = mergeScansParams()
for s in sorted(allScans):
    print(" - %s" % s)
my_scan = get_param_interactive("Choose a scan", "validate_creds", allScans.keys())
# my_scan = get_param_interactive("Choose a scan", "single_bucket_scan", allScans.keys())

(LFName, LOGFILE)=outfile("awsScannerLog")
start_time = time.time()
LOGFILE.write("Scan beginning at %s\n" % datetime.datetime.utcnow().isoformat())
if KEYMODE:
    # check_update_account_file(ACCOUNT_FILE)
    (accounts, deactiveAccounts) = load_accounts(ACCOUNT_FILE, LOGFILE, DEACTIVE_FILE)
    if my_account != 'ALL':
        if my_account == 'LIST':
            accountList=[]
            LOGFILE.write('List holds %s accounts\n' % len(MY_ACCOUNT_LIST))
            for a in MY_ACCOUNT_LIST:
                if a in deactiveAccounts:
                    LOGFILE.write('Account %s is deactivated\n' % a)
                    continue
                tnt=find_tenant(a, accounts)
                if tnt == 'Tenant not found':
                    LOGFILE.write("No account found for Acct#: %s\n" % a)
                    print("No account found for Acct#: %s" % a)
                else:
                    accountList.append({
                        "accountId" : a,
                        "tenantId"  : tnt
                    })
            accounts=accountList
        else:
            my_account = MY_ACCOUNTS.get(my_account, my_account)
            accounts = [{
                "accountId" : my_account,
                "tenantId"  : find_tenant(my_account, accounts)
            }]
    elif my_tenant != 'ALL':
        my_tenant = MY_TENANTS.get(my_tenant, my_tenant)
        accounts = find_accounts(my_tenant, accounts)
else:
    accounts = [{
        "accountId" : "Your Account",
        "tenantId"  : "Your Tenant"
    }]
handle=None
keys=None
accountsTried=0
accountsScanned=0
messages=[]
result=None
region=None
if allScansParams.get(my_scan):
        scanParams={}
        for p in allScansParams[my_scan]:
            scanParams[p]=[]
            while True:
                my_p = get_param_interactive(p)
                if my_p is None:
                    break
                scanParams[p].append(my_p)
for a in accounts:
    if my_mode=='NOTLIST' and a in MY_ACCOUNT_LIST:
        LOGFILE.write("Skipping account %s from list\n" % a)
        continue
    accountsTried+=1
    result=None
    if KEYMODE:
        keys = get_credential(a)
    elif myAccessKey:
        keys = (myAccessKey, mySecretKey)
    if keys and all(keys):
        (a['accessKey'], a['secretKey']) = keys
    elif KEYMODE:
        LOGFILE.write('No keys for Tenant %s and Account %s, skipping.\n' % (a['tenantId'], a['accountId']))
        continue 
    if allScanstype.get(my_scan) == "single_region" :
        region='Not applicable'
        # print("Region is either global or not applicable\n")
        if allScansParams.get(my_scan) is not None:
            (result, handle) = allScans[my_scan](a, LOGFILE, region, handle, scanParams)
        else:
            (result, handle) = allScans[my_scan](a, LOGFILE, region, handle)
        if result:
            accountsScanned+=1
    elif allScanstype.get(my_scan) == "multi_region" :
        r_count = 0
        REGIONS = find_regions(a)
        for region in REGIONS :
            # print( "Now Checking for %s"  % (region))
            try :
               if allScansParams[my_scan]:
                    (result, handle) = allScans[my_scan](a, LOGFILE, region, handle, scanParams)
               else:
                    (result, handle) = allScans[my_scan](a, LOGFILE, region, handle)
               if result:
                   r_count+=1
            except Exception as e:
               print('Exception:')
               print(e)
               print("INFO : %s not available for %s" % (my_scan, region))
        if r_count > 0:
            accountsScanned+=1
    else :
        if allScansParams[my_scan]:
            (result, handle) = allScans[my_scan](a, LOGFILE, region, handle, scanParams)
        else:
            (result, handle) = allScans[my_scan](a, LOGFILE, region, handle)
        if result:
            accountsScanned+=1
            
messages.append("Scanned %s of %s accounts" % (accountsScanned, accountsTried))
if result:
    if result['description']:
        messages.append("for %s" % result["description"])
        messages.append("Found %s positive (bad) results of %s total %s" % (result['matchingResources'], result['totalResources'], result['resourceName']))
        messages.append("see %s for details" % result['outputFileName'])
    else:
        messages=["Failed to scan account %s" % my_account]
# else:
#     result=None
#     a={
#         "accountId" : my_account,
#         "tenantId"  : find_account(my_account, accounts)
#     }
#     keys = get_credential(a)
#     if keys:
#         (a['accessKey'], a['secretKey']) = keys
#         (result, handle) = scan.AWS_SCANS[my_scan](a, LOGFILE, handle)
#     if result:
#         messages.append("Scanned account %s" % my_account)
#         messages.append("Found %s positive results of %s total %s" % (result['matchingResources'], result['totalResources'], result['resourceName']))
#         messages.append("see %s for details" % result['outputFileName'])
#     else:
#         messages=["Failed to scan account %s" % my_account]
for m in messages:
    LOGFILE.write("%s\n" % m)
    print(m)
LOGFILE.write("Scan ending at %s\n" % datetime.datetime.utcnow().isoformat())
elapsed_time = time.time()-start_time
(days,hours,minutes,seconds)=cvtime(elapsed_time)
LOGFILE.write("Elapsed time: %d days %d:%02d:%02d" % (days, hours, minutes, seconds))
LOGFILE.close()
print('Wrote logfile %s' % LFName)
print("Elapsed time: %d days %d:%02d:%02d" % (days, hours, minutes, seconds))