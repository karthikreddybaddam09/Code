import __main__ as main
import boto3,datetime
from botocore.client import ClientError
import json

# Define "modules" here which can be called by awsScanner
    # Passed values should be 
    # {
    #     "tenantId" : x,
    #     "accountId": x,
    #     "accessKey": x,
    #     "secretKey": x
    # }

RESULT = {
    "description"     : None,  #Description of the Scan
    'matchingResources' : 0,   #Number of matches found
    'totalResources' : 0,      #Total number of resources scanned
    'resourceName' : None,     #Display name for the resource e.g. "Buckets"
    'outputFileName' : None    #Name of the output file created
}

def managed_policies_scan(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="AWS Managed Policies"
        RESULT['resourceName']="AWSManagedPolicies"
        (RESULT['outputFileName'],fh)=main.outfile('AWSManagedPolicies')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey']
                    )
    else:
        my_session = boto3.Session()
    my_client = my_session.client('iam')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s\n" % (acct['accountId'], acct['tenantId']))
        my_resources=0
        my_matches=0
        position = fh.tell()
        fh.seek(0)
        if 'TenantId,AccountId,PolicyName,AttachmentCount,UnSafe\n' not in fh.readlines() :
           fh.write('TenantId,AccountId,PolicyName,AttachmentCount,UnSafe\n')
        my_details = my_client.list_policies(Scope='AWS', OnlyAttached=True)
        managed_policy_functions_list_to_ignore = ['AdministratorAccess', 'PowerUserAccess', 'SecurityAudit', 'ReadOnlyAccess']
        for a in my_details.get('Policies'):
            try:
                my_resources+=1
                RESULT['totalResources']+=1
                if a.get('PolicyName') in managed_policy_functions_list_to_ignore :
                   #fh.write("AWS Managed Policy %s is safe as per given list %s and attached to %d users/groups/roles\n" % (a.get('PolicyName'), managed_policy_functions_list_to_ignore, a.get('AttachmentCount')))
                   pass
                else :
                   #fh.write("Error : AWS Managed Policy %s is not safe as per given list %s and attached to %d users/groups/roles\n" % (a.get('PolicyName'), managed_policy_functions_list_to_ignore, a.get('AttachmentCount')) )
                   fh.write('%s,%s,%s,%d,yes\n' % (acct['tenantId'], acct['accountId'],a.get('PolicyName'), a.get('AttachmentCount') ))
                   RESULT['matchingResources'] += 1
                   my_matches += 1

            except ClientError as e:
                LOGFILE.write("WARNING: Cannot see logs (%s) for AWS Managed Policies %s\n" % (e.response['Error']['Code'], a.get('PolicyName')) )
        LOGFILE.write('Scanned %s AWS Managed Policies. %s non-compliant.\n' % (my_resources, my_matches))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s \n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey']))
        return None, fh


def redshift_cluster_scan(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="Redshift Cluster Scan"
        RESULT['resourceName']="redhat_cluster_scan"
        (RESULT['outputFileName'],fh)=main.outfile('RedShiftCluster')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name=region
                    )
    else:
        my_session = boto3.Session(region_name=region)
    my_client = my_session.client('redshift')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_details = my_client.describe_clusters()
        position = fh.tell()
        fh.seek(0)
        if 'Region,TenantId,AccountId,ClusterIdentifier,Publicly Accessible\n' not in fh.readlines() :
           fh.write('Region,TenantId,AccountId,ClusterIdentifier,Publicly Accessible\n')
        for a in my_details.get('Clusters'):
            try:
                my_resources+=1
                RESULT['totalResources']+=1
                if str(a.get('PubliclyAccessible')) != 'True' :
                   pass
                   #fh.write("Redshift Cluster with name %s is safe \n" % (a.get('ClusterIdentifier')))
                else :
                   #fh.write("Error : Redshift Cluster with name %s is not safe \n" % (a.get('ClusterIdentifier')) )
                   fh.write("%s,%s,%s,%s,yes\n" % (region, acct['tenantId'], acct['accountId'], a.get('ClusterIdentifier')) )
                   RESULT['matchingResources'] += 1
                   my_matches += 1

            except ClientError as e:
                LOGFILE.write("WARNING: Cannot see logs (%s) for Redshift cluster %s of %s\n" % (e.response['Error']['Code'], a.get('ClusterIdentifier'), region) )
        LOGFILE.write('Scanned %s Redshift cluster. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'],region))
        return None, fh

def route53_domain_transfer_lock(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="Route 53 Domain Transfer Lock"
        RESULT['resourceName']="Route53DomainTransferLock"
        (RESULT['outputFileName'],fh)=main.outfile('Route53DomainTransferLock')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey']
                    )
    else:
        my_session = boto3.Session()
    my_client = my_session.client('route53domains')
    try:
        fh.write("Scanning Account %s for Tenant %s\n" % (acct['accountId'], acct['tenantId']))
        my_resources=0
        my_matches=0
        my_details = my_client.list_domains()
        for a in my_details.get('Domains'):
            try:
                my_resources+=1
                RESULT['totalResources']+=1
                if str(a.get('TransferLock')).lower() == 'true' :
                   fh.write("Route 53 Domain Transfer of domain %s is locked \n" % (a.get('DomainName')))
                else :
                   fh.write("Error : Route 53 Domain Transfer of domain %s is not locked \n" % (a.get('DomainName')) )
                   RESULT['matchingResources'] += 1
                   my_matches += 1

            except ClientError as e:
                fh.write("WARNING: Cannot see logs (%s) for Route 53 Domain Transfer %s\n" % (e.response['Error']['Code'], a.get('DomainName')) )
        fh.write('Scanned %s Route 53 Domains. %s non-compliant.\n' % (my_resources, my_matches))
        fh.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s \n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey']))
        return None, fh


def ebs_encryption_scan(acct, LOGFILE, region, fh=None):
    print("In scan")
    try:
        if not fh:
            RESULT['description']="EBS Encryption Scan"
            RESULT['resourceName']="ebs_encryption_scan"
            (RESULT['outputFileName'],fh)=main.outfile('EBSEncryption')
            RESULT['matchingResources']=0
            RESULT['totalResources']=0
        if 'secretKey' in acct.keys():
            my_session = boto3.Session(
                        aws_access_key_id=acct['accessKey'],
                        aws_secret_access_key=acct['secretKey'],
                        region_name=region
                        )
        else:
            my_session = boto3.Session(region_name=region)
    except Exception as e:
        print("Error thrown in scan")
        print(e)
        raise
    print("got session")
    try:
        my_client = my_session.client('ec2')
        fh.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_details = my_client.describe_volumes()
        for a in my_details.get('Volumes'):
            try:
                my_resources+=1
                RESULT['totalResources']+=1
                if str(a.get('Encrypted')).lower() == 'true' :
                   fh.write("Encryption enabled on EBS volume with name %s of %s\n" % (a.get('VolumeId'), region))
                else :
                   fh.write("Error : Encryption disabled on EBS volume with name %s of %s\n" % (a.get('VolumeId'), region) )
                   RESULT['matchingResources'] += 1
                   my_matches += 1

            except ClientError as e:
                fh.write("WARNING: Cannot see logs (%s) for EBS Encryption %s of %s\n" % (e.response['Error']['Code'], a.get('VolumeId'), region) )
        fh.write('Scanned %s EBS. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        fh.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh
    except Exception as e:
        print("Error thrown in scan")
        print(e)
        raise

        

def custom_policies_scan(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="AWS Custom Policies"
        RESULT['resourceName']="AWSCustomPolicies"
        (RESULT['outputFileName'],fh)=main.outfile('AWSCustomPolicies')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey']
                    )
    else:
        my_session = boto3.Session()
    my_client = my_session.client('iam')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s\n" % (acct['accountId'], acct['tenantId']))
        my_resources=0
        my_matches=0
        position = fh.tell()
        fh.seek(0)
        if 'TenantId,AccountId,PolicyName,AttachmentCount,UnSafe\n' not in fh.readlines() :
           fh.write('TenantId,AccountId,PolicyName,AttachmentCount,UnSafe\n')
        my_details = my_client.list_policies(Scope='Local', OnlyAttached=True)
        for a in my_details.get('Policies'):
            try:
                my_resources+=1
                RESULT['totalResources']+=1
		version_id = my_client.get_policy(PolicyArn = a.get('Arn')).get('Policy').get('DefaultVersionId')
		policy_doc = my_client.get_policy_version(PolicyArn = a.get('Arn'), VersionId = version_id)
		policy_doc = policy_doc.get('PolicyVersion').get('Document').get('Statement')
		unsafe_count = 0
		for policy_statement in policy_doc :
			try :
				policy_actions = policy_statement.get('Action')
				policy_resource = policy_statement.get('Resource')
				policy_effect = policy_statement.get('Effect')
				if policy_actions == '*' and policy_resource == '*' and policy_effect.lower() == 'allow' :
					unsafe_count += 1
			except :
				fh.write('%s,%s,%s,%d,unknown\n' % (acct['tenantId'], acct['accountId'],a.get('PolicyName'), a.get('AttachmentCount') ))
                if unsafe_count == 0 :
                   #fh.write("AWS Custom Policy %s is safe and attached to %d users/groups/roles\n" % (a.get('PolicyName'), a.get('AttachmentCount')))
                   pass
                else :
                   #fh.write("Error : AWS Custom Policy %s is not safe and attached to %d users/groups/roles\n" % (a.get('PolicyName'), a.get('AttachmentCount')) )
                   fh.write('%s,%s,%s,%d,yes\n' % (acct['tenantId'], acct['accountId'],a.get('PolicyName'), a.get('AttachmentCount') ))
                   RESULT['matchingResources'] += 1
                   my_matches += 1

            except ClientError as e:
                LOGFILE.write("WARNING: Cannot see logs (%s) for AWS Custom Policies %s\n" % (e.response['Error']['Code'], a.get('PolicyName')) )
        LOGFILE.write('Scanned %s AWS Custom Policies. %s non-compliant.\n' % (my_resources, my_matches))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey']))
        return None, fh

def glacier_vault_scan(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="Glacier Vault Scan"
        RESULT['resourceName']="glacier_vault"
        (RESULT['outputFileName'],fh)=main.outfile('glacierVault')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name=region
                    )
    else:
        my_session = boto3.Session(region_name=region)
    my_client = my_session.client('glacier')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        position = fh.tell()
        fh.seek(0)
        if 'Region,TenantId,AccountId,VaultName,Open\n' not in fh.readlines() :
           fh.write('Region,TenantId,AccountId,VaultName,Open\n')
        my_details = my_client.list_vaults()
        for a in my_details.get('VaultList'):
            try:
                my_resources+=1
                RESULT['totalResources']+=1
                response_raw = my_client.get_vault_access_policy(vaultName=a.get('VaultName'))
                response = json.loads(response_raw.get('policy').get('Policy'))
                statements = response.get('Statement')
                chk_count = 0
                for state in statements:
                   try :
                       effect = state.get('Effect')
                       users = state.get('Principal').get('AWS')
                       condition = state.get('Condition')
                       chk = check_policy(effect=effect, users=users, condition=condition )
                       if chk == False :
                          chk_count += 1
                   except : 
                       fh.write("%s,%s,%s,%s,Unknown\n" % (region,acct['tenantId'], acct['accountId'], a.get('VaultName')) )
                if chk_count == 0 :
                   #fh.write("Glacier with Vault %s is safe \n" % (a.get('VaultName')))
                   pass
                else :
                   #fh.write("Error : Glacier with Vault %s is not safe \n" % (a.get('VaultName')) )
                   fh.write("%s,%s,%s,%s,yes\n" % (region,acct['tenantId'], acct['accountId'], a.get('VaultName')) )
                   RESULT['matchingResources'] += 1
                   my_matches += 1

            except ClientError as e:
                LOGFILE.write("WARNING: Cannot see logs (%s) for Glacier %s of %s\n" % (e.response['Error']['Code'], a.get('VaultName'), region) )
        LOGFILE.write('Scanned %s glacier vault. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def key_vault_scan(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="AWS KMS CMK Scan"
        RESULT['resourceName']="AWSKMSCMKScan"
        (RESULT['outputFileName'],fh)=main.outfile('AWSKMSCMKScan')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name=region
                    )
    else:
        my_session = boto3.Session(region_name=region)
    try:
        my_client = my_session.client('ec2')
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        fh.seek(0)
        if 'Region,TenantId,AccountId,VolumeId,Using default key / AWS-managed key\n' not in fh.readlines() :
            fh.write('Region,TenantId,AccountId,VolumeId,Using default key / AWS-managed key\n')
        try :
            my_response = my_client.describe_volumes()
            for p in my_response.get('Volumes'):
                my_resources+=1
                RESULT['totalResources']+=1
                v_id = p.get('VolumeId')
                k_id = p.get('KmsKeyId', "random/random").split('/')[-1]
                my_client_kms = my_session.client('kms')
                keys_out = my_client_kms.list_aliases()
                for i in  keys_out.get('Aliases'):
                    if i.get('TargetKeyId') == k_id :
                        if i.get('AliasName') == "alias/aws/ebs" :
                              RESULT['matchingResources']+=1
                              my_matches+=1
                              fh.write("%s,%s,%s,%s,%s,Yes\n" % ( region, acct['tenantId'], acct['accountId'], v_id ) )
        except ClientError as e:
            LOGFILE.write("WARNING: Cannot describe volume for default keys %s of %s\n" % (e.response['Error']['Code'], region ) )
        LOGFILE.write('Scanned %s volumes. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def cloudfront_cert(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="CloudFront Cert"
        RESULT['resourceName']="cloudFrontCert"
        (RESULT['outputFileName'],fh)=main.outfile('CloudFrontCert')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey']
                    )
    else:
        my_session = boto3.Session()
    try:
        my_client = my_session.client('cloudfront')
        LOGFILE.write("Scanning Account %s for Tenant %s\n" % (acct['accountId'], acct['tenantId']))
        my_resources=0
        my_matches=0
        fh.seek(0)
        if 'TenantId,AccountId,ID,Security Policy,CertificateSource,CertificateARN,CertificateStatus,CertificateIssuer,CertificateType,Compliance\n' not in fh.readlines() :
            fh.write('TenantId,AccountId,ID,Security Policy,CertificateSource,CertificateARN,CertificateStatus,CertificateIssuer,CertificateType,Compliance\n')
        try :
            my_response = my_client.list_distributions()
            for p in my_response.get('DistributionList').get('Items'):
                my_resources+=1
                RESULT['totalResources']+=1
                cf_id = p.get('Id')
                c_source = p.get('ViewerCertificate').get('CertificateSource')
                m_proto = p.get('ViewerCertificate').get('MinimumProtocolVersion')
                c_status = "ISSUED"
                c_arn = None
                cert_region = None
                c_issuer = None
                c_type = None
                if c_source != 'cloudfront' :
                   
                    c_arn = p.get('ViewerCertificate').get('Certificate')
                    try :
                        cert_region = c_arn.split(':')[3]
                        my_session_acm = boto3.Session(region_name=cert_region)
                        my_client_acm = my_session_acm.client('acm')
                        my_response_acm = my_client_acm.describe_certificate(CertificateArn=c_arn)
                        c_status = my_response_acm.get('Certificate').get('Status')
                        c_issuer = my_response_acm.get('Certificate').get('Issuer')
                        c_type = my_response_acm.get('Certificate').get('Type')
                        #exp_date = my_response_acm.get('Certificate').get('NotAfter')
                    except IndexError :
                        pass
                if c_status != "ISSUED" or m_proto not in ['TLSv1.1_2016', 'TLSv1.2_2018'] :
                    fh.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,No\n" % ( acct['tenantId'], acct['accountId'], cf_id, m_proto, c_source, c_arn, c_status, c_issuer, c_type ) )
                    RESULT['matchingResources']+=1
                    my_matches+=1
        except ClientError as e:
            LOGFILE.write("WARNING: Cannot describe CloudFront for information %s\n" % (e.response['Error']['Code']) )
        LOGFILE.write('Scanned %s cloudfront cert. %s non-compliant.\n' % (my_resources, my_matches))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey']))
        return None, fh

def cloud_trail_check(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="CloudTrail Policy Scan"
        RESULT['resourceName']="CloudTrailPolicyScan"
        (RESULT['outputFileName'],fh)=main.outfile('CloudTrailPolicyScan')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name=region
                    )
    else:
        my_session = boto3.Session(region_name=region)
    try:
        my_client = my_session.client('cloudtrail')
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        fh.seek(0)
        if 'Region,TenantId,AccountId,Trail Name,IsMultiRegionTrail,IsLogging,ReadWriteType\n' not in fh.readlines() :
            fh.write('Region,TenantId,AccountId,Trail Name,IsMultiRegionTrail,IsLogging,ReadWriteType\n')
        try :
            my_response = my_client.describe_trails()
            for p in my_response.get('trailList'):
                my_resources+=1
                RESULT['totalResources']+=1
                Name = p.get('Name')
                MultiR = p.get('IsMultiRegionTrail')
                trail = my_client.get_trail_status( Name = p.get('TrailARN') )
                IsLogging = trail.get('IsLogging')
                selector = my_client.get_event_selectors( TrailName = p.get('TrailARN') )
                EventSelectors = selector.get('EventSelectors')
                count = 0
                for i in EventSelectors :
                     i.get('ReadWriteType').lower() != 'all' 
                     count+=1
                if str(MultiR).lower() == 'true' and str(IsLogging).lower() == 'true' and count == 0 : 
                    pass
                else : 
                    RESULT['matchingResources']+=1
                    my_matches+=1
                    fh.write("%s,%s,%s,%s,%s,%s,not all\n" % ( region, acct['tenantId'], acct['accountId'], Name, MultiR, IsLogging ) )
        except ClientError as e:
            LOGFILE.write("WARNING: Cannot describe cloud trail, error %s of %s\n" % (e.response['Error']['Code'], region ) )
        LOGFILE.write('Scanned %s cloud trail. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def elasticsearch_domain_scan(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="Elasticsearch Domain Scan"
        RESULT['resourceName']="elasticsearch_domain"
        (RESULT['outputFileName'],fh)=main.outfile('elasticSearchDomain')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name=region
                    )
    else:
        my_session = boto3.Session(region_name=region)
    my_client = my_session.client('es')
    try:
        fh.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_details = my_client.list_domain_names()
        for a in my_details.get('DomainNames'):
            try:
                my_resources+=1
                RESULT['totalResources']+=1
                response_raw = my_client.describe_elasticsearch_domain(DomainName=a.get('DomainName'))
                response = json.loads(response_raw['DomainStatus']['AccessPolicies'])
                statements = response.get('Statement')
                chk_count = 0
                for state in statements:
                   effect = state.get('Effect')
                   users = state.get('Principal').get('AWS')
                   condition = state.get('Condition')
                   chk = check_policy(effect=effect, users=users, condition=condition )
                   if chk == False :
                      chk_count += 1
                if chk_count == 0 : 
                   fh.write("Elasticsearch with Domain %s is safe of %s\n" % (a.get('DomainName'), region))
                else : 
                   fh.write("Error : Elasticsearch with Domain %s is not safe of %s\n" % (a.get('DomainName'), region) ) 
                   RESULT['matchingResources'] += 1
                   my_matches += 1
                   
            except ClientError as e:
                fh.write("WARNING: Cannot see logs (%s) for Elasticsearch %s of %s\n" % (e.response['Error']['Code'], a.get('DomainName'), region) )
        fh.write('Scanned %s es-domains. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        fh.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def elastic_beanstalk_app_count(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="Elastic BeanStalk app count"
        RESULT['resourceName']="elasticBeanStalkAppCount"
        (RESULT['outputFileName'],fh)=main.outfile('elasticBeanStalkAppCount')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name=region
                    )
    else:
        my_session = boto3.Session(region_name=region)
    my_client = my_session.client('elasticbeanstalk')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        fh.seek(0)
        if 'Region,TenantId,AccountId,AppCounts,AppName list\n' not in fh.readlines() :
            fh.write('Region,TenantId,AccountId,AppCounts,AppName list\n')

        my_details = my_client.describe_applications()
        bs_app_name = []
        for a in my_details.get('Applications'):
            bs_app_name.append(a.get('ApplicationName'))
            my_resources+=1
            RESULT['totalResources']+=1
            # "matchingResources" and "my_matches" have no significance in this scan
            RESULT['matchingResources'] += 1
            my_matches += 1
        fh.write("%s,%s,%s,%d,%s\n" % (region, acct['tenantId'], acct['accountId'], len(bs_app_name), str(bs_app_name).replace(',' , ';').replace('[', '').replace(']','') ) )
        LOGFILE.write('Scanned %s es-beanstalk. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def acm_cert_scan(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="ACM_Cert Scan"
        RESULT['resourceName']="ACM_Cert_Scan"
        (RESULT['outputFileName'],fh)=main.outfile('ACM_Cert_Scan')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name=region
                    )
    else:
        my_session = boto3.Session(region_name=region)
    my_client_acm = my_session.client('acm')
    
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_response_acm_list = my_client_acm.list_certificates()
        
        position = fh.tell()
        fh.seek(0)
        if 'Region,TenantId,AccountId,CertARN,Status,Issuer,Type,Source,NotAfter,DaysToExpire\n' not in fh.readlines() :
            fh.write('Region,TenantId,AccountId,CertARN,Status,Issuer,Type,Source,NotAfter,DaysToExpire\n')
        
        for a in my_response_acm_list['CertificateSummaryList'] :
            my_resources+=1
            RESULT['totalResources']+=1
            c_arn = a.get('CertificateArn')
            my_response_acm = my_client_acm.describe_certificate(CertificateArn=c_arn)
            c_status = my_response_acm.get('Certificate').get('Status')
            c_issuer = my_response_acm.get('Certificate').get('Issuer')
            c_source = "ACM"
            c_type = my_response_acm.get('Certificate').get('Type')
            exp_date = my_response_acm.get('Certificate').get('NotAfter')
            if exp_date :
               tz_info = exp_date.tzinfo
               remaining = exp_date - datetime.datetime.now(tz_info)
               if remaining.days < 0 :
                 RESULT['matchingResources'] += 1
                 my_matches += 1
                 fh.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%d\n" % ( region,acct['tenantId'], acct['accountId'], c_arn, c_status, c_issuer, c_type, c_source, exp_date, remaining.days ) )
            else :
               RESULT['matchingResources'] += 1
               my_matches += 1
               fh.write("%s,%s,%s,%s,%s,%s,%s,%s,Unknown,Unknown\n" % ( region, acct['tenantId'], acct['accountId'], c_arn, c_status, c_issuer, c_type, c_source ) ) 

        LOGFILE.write('Scanned %s instances. %s non-compliant.\n' % (my_resources, my_matches))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey']))
        return None, fh

def iam_cert_scan(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="IAM_Cert Scan"
        RESULT['resourceName']="IAM_Cert_Scan"
        (RESULT['outputFileName'],fh)=main.outfile('IAM_Cert_Scan')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey']          
                    )
    else:
        my_session = boto3.Session()
    my_client_iam = my_session.client('iam')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_response_iam_list = my_client_iam.list_server_certificates()
        position = fh.tell()
        fh.seek(0)
        if 'TenantId,AccountId,CertName,Status,Issuer,Type,Source,NotAfter,DaysToExpire\n' not in fh.readlines() :
            fh.write('TenantId,AccountId,CertName,Status,Issuer,Type,Source,NotAfter,DaysToExpire\n')
        for a in my_response_iam_list['ServerCertificateMetadataList'] :
            my_resources+=1
            RESULT['totalResources']+=1
            c_name = a.get('ServerCertificateName')
            my_response_iam = my_client_iam.get_server_certificate(ServerCertificateName=c_name)
            c_status = None
            c_issuer = None
            c_type = "IAM"
            c_source = "IAM"
            exp_date = my_response_iam.get('ServerCertificate').get('ServerCertificateMetadata').get('Expiration')
            if exp_date :
               tz_info = exp_date.tzinfo
               remaining = exp_date - datetime.datetime.now(tz_info)
               if remaining.days < 0 :
                 RESULT['matchingResources'] += 1
                 my_matches += 1
                 fh.write("%s,%s,%s,%s,%s,%s,%s,%s,%d\n" % ( acct['tenantId'], acct['accountId'], c_name, c_status, c_issuer, c_type, c_source, exp_date, remaining.days ) )
            else :
               RESULT['matchingResources'] += 1
               my_matches += 1
               fh.write("%s,%s,%s,%s,%s,%s,%s,Unknown,Unknown\n" % ( acct['tenantId'], acct['accountId'], c_name, c_status, c_issuer, c_type, c_source ) ) 
        LOGFILE.write('Scanned %s instances. %s non-compliant.\n' % (my_resources, my_matches))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey']))
        return None, fh

def rds_instance_encryption_scan(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="RDS Instance Encryption Scan"
        RESULT['resourceName']="RDSInstanceEncryptionScan"
        (RESULT['outputFileName'],fh)=main.outfile('RDSInstanceEncryption')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name=region
                    )
    else:
        my_session = boto3.Session(region_name=region)
    my_client = my_session.client('rds')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_details = my_client.describe_db_instances()
        position = fh.tell()
        fh.seek(0)
        if 'Region,TenantId,AccountId,DBInstanceIdentifier,Encryption\n' not in fh.readlines() :
           fh.write('Region,TenantId,AccountId,DBInstanceIdentifier,Encryption\n')
        for a in my_details.get('DBInstances'):
            try:
                my_resources+=1
                RESULT['totalResources']+=1
                if str(a.get('StorageEncrypted')).lower() == 'true' :
                   pass
                else :
                   fh.write("%s,%s,%s,%s,No\n" % (region, acct['tenantId'], acct['accountId'], a.get('DBInstanceIdentifier')) )
                   RESULT['matchingResources'] += 1
                   my_matches += 1

            except ClientError as e:
                LOGFILE.write("WARNING: Cannot check rds instance encryption (%s) for Rds instance %s of %s\n" % (e.response['Error']['Code'], a.get('DBInstanceIdentifier'), region) )
        LOGFILE.write('Scanned %s RDS instances. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'],region))
        return None, fh

def vpc_flow_logs(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="VPC flow logs"
        RESULT['resourceName']="Vpcflowlogs"
        (RESULT['outputFileName'],fh)=main.outfile('vpcflowlogs')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name= region
                    )
    else:
        my_session = boto3.Session(region_name=region)
    my_client = my_session.client('ec2')
    response = my_client.describe_vpcs()
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        fh.seek(0)
        if 'Region,TenantId,AccountId,vpc,flowlogs\n' not in fh.readlines() :
            fh.write('Region,TenantId,AccountId,vpc,flowlogs\n')
        for vpc in response["Vpcs"]:
            my_resources+=1
            RESULT['totalResources']+=1
            vpc = vpc["VpcId"]
            r = my_client.describe_flow_logs( Filter=[{ 'Name': 'resource-id', 'Values': [ vpc ]}, ],)
            if not r['FlowLogs'] : 
				fh.write("%s,%s,%s,%s,No\n" % (region,acct['tenantId'],acct['accountId'],vpc))
				RESULT['matchingResources'] += 1
				my_matches += 1
       
        
        LOGFILE.write('Scanned %s VPC. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def vpc_flow_logs(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="VPC flow logs"
        RESULT['resourceName']="Vpcflowlogs"
        (RESULT['outputFileName'],fh)=main.outfile('vpcflowlogs')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name= region
                    )
    else:
        my_session = boto3.Session(region_name=region)
    my_client = my_session.client('ec2')
    response = my_client.describe_vpcs()
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        fh.seek(0)
        if 'Region,TenantId,AccountId,vpc,flowlogs\n' not in fh.readlines() :
            fh.write('Region,TenantId,AccountId,vpc,flowlogs\n')
        for vpc in response["Vpcs"]:
            my_resources+=1
            RESULT['totalResources']+=1
            vpc = vpc["VpcId"]
            r = my_client.describe_flow_logs( Filter=[{ 'Name': 'resource-id', 'Values': [ vpc ]}, ],)
            if not r['FlowLogs'] : 
				fh.write("%s,%s,%s,%s,No\n" % (region,acct['tenantId'],acct['accountId'],vpc))
				RESULT['matchingResources'] += 1
				my_matches += 1
       
        
        LOGFILE.write('Scanned %s VPC. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def Guard_duty_enable_check(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="Guardduty"
        RESULT['resourceName']="Guardduty"
        (RESULT['outputFileName'],fh)=main.outfile('Guardduty')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name= region
                    )
    else:
        my_session = boto3.Session(region_name=region)
    my_client = my_session.client('guardduty')
    response = my_client.list_detectors()
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        fh.seek(0)
        if 'Region,TenantId,AccountId,Guardduty,Status\n' not in fh.readlines() :
            fh.write('Region,TenantId,AccountId,Guardduty,Status\n')
        my_resources+=1
        RESULT['totalResources']+=1
        value = response['DetectorIds']
        if value : 
            r = my_client.get_detector(DetectorId=value[0])
            if r.get('Status') == "Enabled" :
                pass
            else:
                fh.write("%s,%s,%s,%s,Not Enabled\n" % (region,acct['tenantId'],acct['accountId'],value[0]))
                RESULT['matchingResources'] += 1
                my_matches += 1
        else :
            fh.write("%s,%s,%s,No Detector Found,NA\n" % (region,acct['tenantId'],acct['accountId']))
            RESULT['matchingResources'] += 1
            my_matches += 1

        LOGFILE.write('Scanned %s guardduty. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def ebs_encryption_scan_2222(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="EBS Encryption Scan"
        RESULT['resourceName']="ebs_encryption_scan"
        (RESULT['outputFileName'],fh)=main.outfile('EBSEncryption')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name=region
                    )
    else:
        my_session = boto3.Session(region_name=region)
    my_client = my_session.client('ec2')
    position = fh.tell()
    fh.seek(0)
    if 'Region,TenantId,AccountId,VolumID,Encrypted\n' not in fh.readlines() :
       fh.write('Region,TenantId,AccountId,VolumID,Encrypted\n')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        current_date = datetime.datetime.utcnow()
        my_details = my_client.describe_volumes()
        for a in my_details.get('Volumes'):
            volume_create_time = a.get('CreateTime').replace(tzinfo=None) 
            day_left = current_date - volume_create_time
            day_left = day_left.days
            if day_left <= 1 :
                continue 
            try:
                my_resources+=1
                RESULT['totalResources']+=1
                if str(a.get('Encrypted')).lower() == 'true' :
                   #fh.write('%s,%s,%s,%s,Yes\n' % (region, acct['tenantId'], acct['accountId'],a.get('VolumeId')))
                   pass
                else :
                   fh.write('%s,%s,%s,%s,No\n' % (region, acct['tenantId'], acct['accountId'],a.get('VolumeId')))
                   RESULT['matchingResources'] += 1
                   my_matches += 1

            except ClientError as e:
                LOGFILE.write("WARNING: Cannot see logs (%s) for EBS Encryption %s of %s\n" % (e.response['Error']['Code'], a.get('VolumeId'), region) )
        LOGFILE.write('Scanned %s EBS. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def redshift_audit_logging(acct, LOGFILE, region, fh=None):
		  
    remediation = "no"
    if not fh:
        RESULT['description']="RedShift Audit Logging"
        RESULT['resourceName']="RedShiftAuditLogging"
        (RESULT['outputFileName'],fh)=main.outfile('RedShiftAuditLogging')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name=region
                    )
    else:
        my_session = boto3.Session(region_name=region)
    fh.seek(0)
    if 'Region,AccountId,TenantId,ClusterIdentifier,Logging,Action(if any)\n' not in fh.readlines() :
       fh.write('Region,AccountId,TenantId,ClusterIdentifier,Logging,Action(if any)\n')
    try :
        my_client = my_session.client('redshift')
        redshift_list = [i['ClusterIdentifier'] for i in my_client.describe_clusters()['Clusters']]
        my_resources=0
        my_matches=0
        for i in redshift_list :
            my_resources+=1
            RESULT['totalResources']+=1
            response = my_client.describe_logging_status(ClusterIdentifier=i)
            if response.get('LoggingEnabled') : 
                fh.write("%s,%s,%s,%s,Enabled,NA\n" % (region,acct['accountId'], acct['tenantId'],i))
            else :
                if remediation.lower() == 'yes' : 
                    #my_client.enable_logging(ClusterIdentifier=i, BucketName='', S3KeyPrefix='' )
                    #fh.write("%s,%s,%s,%s,Not Enabled,Fixed\n" % (region,acct['accountId'], acct['tenantId'],i))
                    pass
                else :
                    fh.write("%s,%s,%s,%s,Not Enabled,Not Fixed\n" % (region,acct['accountId'], acct['tenantId'],i))
                RESULT['matchingResources']+=1
                my_matches+=1
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s for %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def es_encryption(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="ES Encryption"
        RESULT['resourceName']="ESEncryption"
        (RESULT['outputFileName'],fh)=main.outfile('ESEncryption')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name=region
                    )
    else:
        my_session = boto3.Session(region_name=region)
    my_client = my_session.client('es')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_details = my_client.list_domain_names()
        position = fh.tell()
        fh.seek(0)
        if 'Region,AccountId,TenantId,DomainName,Endpoint,Encryption\n' not in fh.readlines() :
            fh.write('Region,AccountId,TenantId,DomainName,Endpoint,Encryption\n')
        es_list = my_details.get('DomainNames')
        for a in es_list:
            my_resources+=1
            RESULT['totalResources']+=1
            r=my_client.describe_elasticsearch_domains(DomainNames=[a.get('DomainName')])['DomainStatusList']
            if not r[0].get('EncryptionAtRestOptions').get('Enabled') : fh.write("%s,%s,%s,%s,%s,%s\n" % (region, acct['accountId'], acct['tenantId'], a.get('DomainName'), r[0].get('Endpoint'), r[0].get('EncryptionAtRestOptions').get('Enabled') ))
            RESULT['matchingResources'] += 1
            my_matches += 1
        LOGFILE.write('Scanned %s ES. %s total of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def lb_list(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="LB List"
        RESULT['resourceName']="lb_list"
        (RESULT['outputFileName'],fh)=main.outfile('LBList')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name=region
                    )
    else:
        my_session = boto3.Session(region_name=region)
    my_client = my_session.client('elbv2')
    my_client2 = my_session.client('elb')
    my_clientcdn = my_session.client('cloudfront')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_details = my_client.describe_load_balancers()
        my_details2 = my_client2.describe_load_balancers()
        my_cdn = my_clientcdn.list_distributions()
        position = fh.tell()
        fh.seek(0)
        if 'Region,AccountId,TenantId,VpcId,LoadBalancerName/DistributionId,DNSName,Type\n' not in fh.readlines() :
            fh.write('Region,AccountId,TenantId,VpcId,LoadBalancerName/DistributionId,DNSName,Type\n')
        lb_list = my_details.get('LoadBalancers')
        lb_list.extend(my_details2.get('LoadBalancerDescriptions'))
        for a in lb_list:
            my_resources+=1
            RESULT['totalResources']+=1
            fh.write("%s,%s,%s,%s,%s,%s,LB\n" % (region, acct['accountId'], acct['tenantId'], a.get('VpcId'), a.get('LoadBalancerName'), a.get('DNSName') ))
            RESULT['matchingResources'] += 1
            my_matches += 1
        if  my_cdn['DistributionList'].get('Items'):
            for a in my_cdn['DistributionList']['Items']:
                my_resources+=1
                RESULT['totalResources']+=1
                fh.write("%s,%s,%s,%s,%s,%s,CF\n" % (region, acct['accountId'], acct['tenantId'], a.get('VpcId'), a.get('Id'), a.get('DomainName') ))
                RESULT['matchingResources'] += 1
                my_matches += 1
        LOGFILE.write('Scanned %s ALB/ELB/NLB/CF. %s total of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def Inactive_user_335(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="Housekeeping For User Accounts Resources"
        RESULT['resourceName']="Housekeeping For User Accounts Resources"
        (RESULT['outputFileName'],fh)=main.outfile('SecurityReport')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    )
    else:
        my_session = boto3.Session()
    my_client = my_session.client('iam')
    fh.seek(0)
    if 'AccountId,TenantId,User,Password/AccessKey Last Used,Days Last Used,Created\n' not in fh.readlines() :
            fh.write('AccountId,TenantId,User,Password/AccessKey Last Used,Days Last Used,Created\n')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s\n" % (acct['accountId'], acct['tenantId']))
        my_resources=0
        my_matches=0
        my_acct_details = my_client.list_users()['Users']
        date_now = datetime.datetime.now()
        for user in my_acct_details:
            my_resources+=1
            RESULT['totalResources']+=1
            uname = user['UserName']
            ucdate = user['CreateDate']
            tz_info = ucdate.tzinfo
            if user.get('PasswordLastUsed'):
                upassused = user['PasswordLastUsed']
                lastusedday = datetime.datetime.now(tz_info) - upassused
                if lastusedday > datetime.timedelta(days=90):
                    fh.write("%s,%s,%s,%s,%s,%s\n" % (acct['accountId'], acct['tenantId'], uname, upassused, lastusedday.days, ucdate))
                    RESULT['matchingResources'] += 1
                    my_matches += 1
            else:
                ukey = my_client.list_access_keys(UserName=uname)
                for k in ukey['AccessKeyMetadata']:
                    AccessKeyId = k.get('AccessKeyId')
                    ukeyused_data = my_client.get_access_key_last_used(AccessKeyId=AccessKeyId) 
                    if ukeyused_data.get('AccessKeyLastUsed').get('LastUsedDate'):
                        ukeyused = ukeyused_data.get('AccessKeyLastUsed').get('LastUsedDate')
                        lastusedday = datetime.datetime.now(tz_info) - ukeyused
                        if lastusedday > datetime.timedelta(days=90):
                            fh.write("%s,%s,%s,%s,%s,%s\n" % (acct['accountId'], acct['tenantId'], uname, ukeyused, lastusedday.days, ucdate))
                            RESULT['matchingResources'] += 1
                            my_matches += 1
                    else:
                        fh.write("%s,%s,%s,NA,NA,%s\n" % (acct['accountId'], acct['tenantId'], uname, ucdate))
                        RESULT['matchingResources'] += 1
                        my_matches += 1

        LOGFILE.write('Scanned %s iam users. %s non-compliant.\n' % (my_resources, my_matches))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey']))
        return None, fh

def access_for_dms_replication_instances_246(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="Access for DMS Replication Instances"
        RESULT['resourceName']="Access for DMS Replication Instances"
        (RESULT['outputFileName'],fh)=main.outfile('AccessforDMSReplicationInstances')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name = region
                    )
    else:
        my_session = boto3.Session(region_name = region)
    my_client = my_session.client('dms')
    fh.seek(0)
    if 'Region,AccountId,TenantId,ReplicationInstanceIdentifier,ReplicationInstanceArn,VpcId,PubliclyAccessible\n' not in fh.readlines() :
            fh.write('Region,AccountId,TenantId,ReplicationInstanceIdentifier,ReplicationInstanceArn,VpcId,PubliclyAccessible\n')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_details = my_client.describe_replication_instances()['ReplicationInstances']
        for u in my_details:
            my_resources+=1
            RESULT['totalResources']+=1
            ReplicationInstanceArn = u['ReplicationInstanceArn']
            VpcId = u['ReplicationSubnetGroup']['VpcId']
            ReplicationInstanceIdentifier = u['ReplicationInstanceIdentifier']
            PubliclyAccessible = u.get('PubliclyAccessible')
            if PubliclyAccessible :
                fh.write("%s,%s,%s,%s,%s,%s,%s\n" % (region, acct['accountId'], acct['tenantId'], ReplicationInstanceIdentifier, ReplicationInstanceArn, VpcId, PubliclyAccessible ))
                RESULT['matchingResources'] += 1
                my_matches += 1

        LOGFILE.write('Scanned %s dms. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def master_username_for_rds_316(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="Master Username for RDS"
        RESULT['resourceName']="Master Username for RDS"
        (RESULT['outputFileName'],fh)=main.outfile('MasterUsernameforRDS')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name = region
                    )
    else:
        my_session = boto3.Session(region_name = region)
    my_client = my_session.client('rds')
    fh.seek(0)
    if 'Region,AccountId,TenantId,DBClusterIdentifier,DBClusterArn,MasterUsername\n' not in fh.readlines() :
            fh.write('Region,AccountId,TenantId,DBClusterIdentifier,DBClusterArn,MasterUsername\n')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_details = my_client.describe_db_clusters()['DBClusters']
        for u in my_details:
            my_resources+=1
            RESULT['totalResources']+=1
            MasterUsername = u['MasterUsername']
            DBClusterArn = u['DBClusterArn']            
            DBClusterIdentifier = u['DBClusterIdentifier']
            if MasterUsername.lower() == 'awsuser' :
                fh.write("%s,%s,%s,%s,%s,%s\n" % (region, acct['accountId'], acct['tenantId'], DBClusterIdentifier, DBClusterArn, MasterUsername ))
                RESULT['matchingResources'] += 1
                my_matches += 1

        LOGFILE.write('Scanned %s rds. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def iam_roles_for_emrfs_requests_to_amazon_s3_228(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="IAM roles for EMRFS requests to Amazon S3"
        RESULT['resourceName']="IAM roles for EMRFS requests to Amazon S3"
        (RESULT['outputFileName'],fh)=main.outfile('IAMrolesforEMRFSrequeststoAmazonS3')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name = region
                    )
    else:
        my_session = boto3.Session(region_name = region)
    my_client = my_session.client('emr')
    fh.seek(0)
    if 'Region,AccountId,TenantId,Name,Id,SecurityConfiguration,AuthorizationConfiguration,Status\n' not in fh.readlines() :
            fh.write('Region,AccountId,TenantId,Name,Id,SecurityConfiguration,AuthorizationConfiguration,Status\n')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_details = my_client.list_clusters()['Clusters']
        for u in my_details:
            c_status = u.get('Status').get('State')
            my_resources+=1
            RESULT['totalResources']+=1
            Id = u['Id']
            Name = u['Name']
            SecurityConfiguration = my_client.describe_cluster(ClusterId=Id)['Cluster'].get('SecurityConfiguration')
            if SecurityConfiguration:
                AuthorizationConfiguration = my_client.describe_security_configuration(Name=SecurityConfiguration).get('AuthorizationConfiguration')
                if not AuthorizationConfiguration :
                    fh.write("%s,%s,%s,%s,%s,%s,No,%s\n" % (region, acct['accountId'], acct['tenantId'], Name, Id, SecurityConfiguration,c_status))
                    RESULT['matchingResources'] += 1
                    my_matches += 1
            else:
                fh.write("%s,%s,%s,%s,%s,No,NA,%s\n" % (region, acct['accountId'], acct['tenantId'], Name, Id, c_status))
                RESULT['matchingResources'] += 1
                my_matches += 1

        LOGFILE.write('Scanned %s emr. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def cloudwatch_log_group_retention_264(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="cloudwatch log group retention"
        RESULT['resourceName']="cloudwatch log group retention"
        (RESULT['outputFileName'],fh)=main.outfile('cloudwatchloggroupretention')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name = region
                    )
    else:
        my_session = boto3.Session(region_name = region)
    my_client = my_session.client('logs')
    fh.seek(0)
    if 'Region,AccountId,TenantId,logGroupName\n' not in fh.readlines() :
            fh.write('Region,AccountId,TenantId,logGroupName\n')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_details = my_client.describe_log_groups()['logGroups']
        try:
            for u in my_details:
                my_resources+=1
                RESULT['totalResources']+=1
                logGroupName = u['logGroupName']
                if u.get('retentionInDays') < 30 :
                    fh.write("%s,%s,%s,%s\n" % (region, acct['accountId'], acct['tenantId'], logGroupName ))
                    RESULT['matchingResources'] += 1
                    my_matches += 1

            LOGFILE.write('Scanned %s dms. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
            LOGFILE.write('--------------------\n')
            return RESULT, fh
        except ClientError as e:
            LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
            return None, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def REDIS_AUTH_TOKEN_286(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="REDIS AUTH TOKEN"
        RESULT['resourceName']="REDIS AUTH TOKEN"
        (RESULT['outputFileName'],fh)=main.outfile('REDIS AUTH TOKEN')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name = region
                    )
    else:
        my_session = boto3.Session(region_name = region)
    my_client = my_session.client('elasticache')
    fh.seek(0)
    if 'Region,AccountId,TenantId,Name,ClusterName,AuthTokenEnabled\n' not in fh.readlines() :
        fh.write('Region,AccountId,TenantId,Name,ClusterName,AuthTokenEnabled\n')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_details = my_client.describe_cache_clusters()['CacheClusters']
        for u in my_details:
            my_resources+=1
            RESULT['totalResources']+=1
            ClusterName = u['CacheClusterId']
            AuthTokenEnabled = u['AuthTokenEnabled']
            if AuthTokenEnabled == False:
                    fh.write("%s,%s,%s,%s,%s\n" % (region, acct['accountId'], acct['tenantId'],ClusterName,AuthTokenEnabled))
                    RESULT['matchingResources'] += 1
                    my_matches += 1
        LOGFILE.write('Scanned %s  redis cluster. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def aws_service_role_for_config_332(acct, LOGFILE, region, fh=None,):
    if not fh:
        RESULT['description']="aws service role for config"
        RESULT['resourceName']="aws service role for config"
        (RESULT['outputFileName'],fh)=main.outfile('awsserviceroleforconfig')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey']
                    )
    else:
        my_session = boto3.Session()
    my_client = my_session.client('config')
   
    fh.seek(0)
    if 'AccountId,TenantId,Status\n' not in fh.readlines() :
            fh.write('AccountId,TenantId,Status\n')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s\n" % (acct['accountId'], acct['tenantId']))
        my_resources=0
        my_matches=0
        my_details = my_client.describe_configuration_recorders()
        print my_details
        my_resources+=1
        RESULT['totalResources']+=1        
        if not my_details.get('ConfigurationRecorders'):
            fh.write("%s,%s,No\n" % (acct['accountId'], acct['tenantId'] ))
            RESULT['matchingResources'] += 1
            my_matches += 1

        LOGFILE.write('Scanned %s rds. %s non-compliant.\n' % (my_resources, my_matches))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey']))
        return None, fh

def unencrypted_DMS_Endpoint_Connections_249(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="unencryptedEndpointConnections"
        RESULT['resourceName']="unencryptedEndpointConnections"
        (RESULT['outputFileName'],fh)=main.outfile('unencryptedEndpointConnections')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name = region
                    )
    else:
        my_session = boto3.Session(region_name = region)
    my_client = my_session.client('dms')
    fh.seek(0)
    if 'Region,AccountId,TenantId,Endpoint,Identifier,Mode\n' not in fh.readlines() :
        fh.write('Region,AccountId,TenantId,Endpoint,Identifier,Mode\n')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_details = my_client.describe_endpoints()
        ssl = my_details['Endpoints']
        for u in ssl:
            if u['SslMode'] == "none":
                my_resources+=1
                RESULT['totalResources']+=1
                Identifier = u['EndpointIdentifier']
                Mode = u['SslMode']
                Endpoint = u['EndpointArn']
                fh.write("%s,%s,%s,%s,%s,%s\n" % (region, acct['accountId'], acct['tenantId'],Endpoint,Identifier,Mode))
                my_matches += 1
                RESULT['matchingResources'] +=1
                    
        LOGFILE.write('Scanned %s  dms. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def SNS_HTTPS_Subscription_320(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="SNS HTTPS Subscription"
        RESULT['resourceName']="SNSHTTPSSubscription"
        (RESULT['outputFileName'],fh)=main.outfile('SNS HTTPS Subscription')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name = region
                    )
    else:
        my_session = boto3.Session(region_name = region)
    my_client = my_session.client('sns')
    fh.seek(0)
    if 'Region,AccountId,TenantId,Subscription,Endpoint,protocol\n' not in fh.readlines() :
        fh.write('Region,AccountId,TenantId,Subscription,Endpoint,protocol\n')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_details = my_client.list_subscriptions()
        res = my_details['Subscriptions'] 
        for u in res:
            if u['Protocol'] != 'https':
                my_resources+=1
                RESULT['totalResources']+=1
                Subscription = u['SubscriptionArn']
                protocol = u['Protocol']
                Endpoint = u['Endpoint']
                fh.write("%s,%s,%s,%s,%s,%s\n" % (region, acct['accountId'], acct['tenantId'],Subscription,Endpoint,protocol))
                my_matches += 1
                RESULT['matchingResources'] +=1    
        LOGFILE.write('Scanned %s  SNS. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def kinesis_Customer_Managed_Policy_112(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="kinesis Customer Managed Policy"
        RESULT['resourceName']="kinesis Customer Managed Policy"
        (RESULT['outputFileName'],fh)=main.outfile('kinesis Customer Managed Policy')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey']
                    )
    else:
        my_session = boto3.Session()
    my_client = my_session.client('iam')
    fh.seek(0)
    if 'AccountId,TenantId,PolicyName,PolicyArn\n' not in fh.readlines() :
        fh.write('AccountId,TenantId,PolicyName,PolicyArn\n')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_details = my_client.list_policies(Scope = 'AWS',OnlyAttached = True)
        response = my_details['Policies']
        for u in response:
            my_resources+=1
            RESULT['totalResources']+=1
            if 'Kinesis' in u['Arn']:
                PolicyArn = u['Arn']
                PolicyName = u['PolicyName']
                fh.write("%s,%s,%s,%s\n" % (acct['accountId'], acct['tenantId'],PolicyName,PolicyArn))
                my_matches += 1
                RESULT['matchingResources'] +=1
        LOGFILE.write('Scanned %s  policy. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def default_redshift_port_348(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="default redshift port"
        RESULT['resourceName']="default redshift port"
        (RESULT['outputFileName'],fh)=main.outfile('defaultredshiftport')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name = region
                    )
    else:
        my_session = boto3.Session(region_name = region)
    my_client = my_session.client('redshift')
    fh.seek(0)
    if 'Region,AccountId,TenantId,ClusterIdentifier\n' not in fh.readlines() :
            fh.write('Region,AccountId,TenantId,ClusterIdentifier\n')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_details = my_client.describe_clusters()
        my_cluster_details =  my_details['Clusters']
        for u in my_cluster_details:
            my_resources+=1
            RESULT['totalResources']+=1
            port =  u['Endpoint']['Port']
            ClusterIdentifier = u['ClusterIdentifier']
            if port == 5439:
                fh.write("%s,%s,%s,%s\n" % (region, acct['accountId'], acct['tenantId'],ClusterIdentifier))
                RESULT['matchingResources'] += 1
                my_matches += 1

        LOGFILE.write('Scanned %s redshift. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh
    
def Enabling_Version_Upgrade_for_Redshift_346(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="Enabling Version Upgrade for Redshift"
        RESULT['resourceName']="Enabling Version Upgrade for Redshift"
        (RESULT['outputFileName'],fh)=main.outfile('Enabling Version Upgrade for Redshift')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name = region
                    )
    else:
        my_session = boto3.Session(region_name = region)
    my_client = my_session.client('redshift')
    fh.seek(0)
    if 'Region,AccountId,TenantId,ClusterIdentifier,VersionUpgrade\n' not in fh.readlines() :
        fh.write('Region,AccountId,TenantId,ClusterIdentifier,VersionUpgrade\n')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_details = my_client.describe_clusters()
        response = my_details['Clusters'] 
        for u in response:
            my_resources+=1
            RESULT['totalResources']+=1
            ClusterIdentifier = u['ClusterIdentifier']
            VersionUpgrade = u['AllowVersionUpgrade']
            if u['AllowVersionUpgrade'] == False:
                fh.write("%s,%s,%s,%s,%s\n" % (region, acct['accountId'], acct['tenantId'],ClusterIdentifier,VersionUpgrade))
                my_matches += 1
                RESULT['matchingResources'] +=1
        LOGFILE.write('Scanned %s  Redshift. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def Encryption_for_Kinesis_113(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="Encryption for Kinesis"
        RESULT['resourceName']="Encryption for Kinesis"
        (RESULT['outputFileName'],fh)=main.outfile('Encryption for Kinesis')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name = region
                    )
    else:
        my_session = boto3.Session(region_name = region)
    my_client = my_session.client('kinesis')
    fh.seek(0)
    if 'Region,AccountId,TenantId,streamNames,EncryptionType\n' not in fh.readlines() :
        fh.write('Region,AccountId,TenantId,streamNames,EncryptionType\n')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_details = my_client.list_streams()['StreamNames'] 
        for i in my_details:
            streamNames = i
            my_resources+=1
            RESULT['totalResources']+=1
            my_response = my_client.describe_stream(StreamName = streamNames)
            EncryptionType = my_response['StreamDescription']['EncryptionType']
            if my_response['StreamDescription']['EncryptionType'] == 'NONE':
                fh.write("%s,%s,%s,%s,%s\n" % (region, acct['accountId'], acct['tenantId'],streamNames,EncryptionType))
                my_matches += 1
                RESULT['matchingResources'] +=1
        LOGFILE.write('Scanned %s  kinesis. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def certified_DB_Engine_format(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="Certified Db Engine format"
        RESULT['resourceName']="Certified Db Engine format"
        (RESULT['outputFileName'],fh)=main.outfile('Certified Db Engine format')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name = region
                    )
    else:
        my_session = boto3.Session(region_name = region)
    my_client = my_session.client('dms')
    fh.seek(0)
    if 'Region,AccountId,TenantId,EndpointIdentifier,DBInstanceIdentifier,Engine\n' not in fh.readlines() :
        fh.write('Region,AccountId,TenantId,EndpointIdentifier,DBInstanceIdentifier,Engine\n')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_response = my_client.describe_endpoints()['Endpoints']
        my_resources+=1
        RESULT['totalResources']+=1
        for u in my_response:
            EndpointIdentifier = u['EndpointIdentifier']
            my_client1 = my_session.client('rds')
            response = my_client1.describe_db_instances(DBInstanceIdentifier = EndpointIdentifier )['DBInstances']
            for i in response:
                DBInstanceIdentifier = i['DBInstanceIdentifier']
                Engine = i['Engine']
                if Engine == 'sqlserver-ex':
                    fh.write("%s,%s,%s,%s,%s,%s\n" % (region, acct['accountId'], acct['tenantId'],EndpointIdentifier,DBInstanceIdentifier,Engine))
                    my_matches += 1
                    RESULT['matchingResources'] +=1
        LOGFILE.write('Scanned %s  Endpoint. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def Default_SecurityGroup_for_replication_instance_must_not_be_used_248(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="Default Security Group for replication instance must not be used"
        RESULT['resourceName']="Replication Instances"
        (RESULT['outputFileName'],fh)=main.outfile('Replication Instances')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name = region
                    )
    else:
        my_session = boto3.Session(region_name = region)
    my_client = my_session.client('dms')
    fh.seek(0)
    if 'Region,AccountId,TenantId,ReplicationInstanceIdentifier,SecurityGroupId,GroupName\n' not in fh.readlines() :
        fh.write('Region,AccountId,TenantId,ReplicationInstanceIdentifier,SecurityGroupId,GroupName\n')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_response = my_client.describe_replication_instances()['ReplicationInstances']
        my_resources+=1
        RESULT['totalResources']+=1
        for k in my_response:
            ReplicationInstanceIdentifier = k['ReplicationInstanceIdentifier']
            SecurityGroupId = k['VpcSecurityGroups'][0]['VpcSecurityGroupId']
            Client = my_session.client('ec2')
            response = Client.describe_security_groups(GroupIds = [SecurityGroupId])['SecurityGroups']
            for i in response:
				GroupName = i['GroupName']
				if i['GroupName'] == 'default':
					fh.write("%s,%s,%s,%s,%s,%s\n" % (region, acct['accountId'], acct['tenantId'],ReplicationInstanceIdentifier,SecurityGroupId,GroupName))
					RESULT['matchingResources'] += 1
					my_matches += 1
        LOGFILE.write('Scanned %s  Replication Instances . %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def cyber_ark_IAM(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="Powershell IAM Scanner"
        RESULT['resourceName']="Powershell IAM Scanner"
        (RESULT['outputFileName'],fh)=main.outfile('PowershellIAMScanner')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    try:
        import subprocess, os
        if not os.path.exists('SkyArk'):
            giturl = 'https://github.com/cyberark/SkyArk.git'
            cmd = ['git', 'clone', giturl]
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
            p.communicate()
            cmd = ["powershell.exe", "Install-Module", ".\SkyArk.ps1", "-force"]
            wd = os.getcwd()
            os.chdir(".\SkyArk")
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
            os.chdir(wd)
            p.communicate()
        else:
            print("Git repo already cloned")
    except:
        return None, fh

    if 'secretKey' in acct.keys():
        aws_access_key_id=acct['accessKey']
        aws_secret_access_key=acct['secretKey']
        region_name = 'us-east-1'
        cmd = "powershell.exe Import-Module .\SkyArk.ps1;Scan-AWShadowAdmins -accesskeyid " +  aws_access_key_id +  " -secretkey " +  aws_secret_access_key + " -defaultregion " + region_name
    else:
        cmd = "powershell.exe Import-Module .\SkyArk.ps1;Scan-AWShadowAdmins -ProfileName default -DefaultRegion us-east-1"
    wd = os.getcwd()
    os.chdir(".\SkyArk")
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    os.chdir(wd)
    p.communicate()
    print(os.getcwd())
    
    fh.seek(0)
    if 'AccountId,TenantId,EntityName,EntityType,PrivilegeType,PolicyName,PolicyType,MFAenable,policyCondition,GroupMembers,AssumeRolePolicyDocument,Arn,PrivilegedPermissionPolicy\n' not in fh.readlines():
        fh.write('AccountId,TenantId,EntityName,EntityType,PrivilegeType,PolicyName,PolicyType,MFAenable,policyCondition,GroupMembers,AssumeRolePolicyDocument,Arn,PrivilegedPermissionPolicy\n')
    with open('SkyArk/AWStealth/AWStealth - Results.csv') as fr:
        data = fr.read()
    for l in data.split('"\n"')[1:]:
        lines = l.split('","')
        if lines[1].lower() != 'user':
            lines = l.replace('"",""', ';').split('","')
        line = []
        for i in lines:
            line.append(i.replace('\n', '').replace(',', ';').replace('""','"'))
        csv_line = ','.join(line)
        fh.write("%s,%s,%s\n" % (acct['accountId'], acct['tenantId'], csv_line))
    LOGFILE.write('--------------------\n')
    return RESULT, fh

def bucket_encryption_auto_remediation(acct, LOGFILE, region, fh=None):
    remediation = "yes"
    if not fh:
        RESULT['description']="Bucket Encryption"
        RESULT['resourceName']="BucketsEncryption"
        (RESULT['outputFileName'],fh)=main.outfile('BucketEncryption')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey']
                    )
    else:
        my_session = boto3.Session()
    try :
        my_client = my_session.client('s3')
        bucket_list = [i['Name'] for i in my_client.list_buckets()['Buckets']]
        my_resources=0
        my_matches=0
        fh.seek(0)
        if 'AccountId,TenantId,Bucket,Encryption,Key\n' not in fh.readlines() :
            fh.write('AccountId,TenantId,Bucket,Encryption,Key\n')
        for i in bucket_list :
            my_resources+=1
            RESULT['totalResources']+=1
            response = my_client.get_bucket_location( Bucket=i)
            try : 
                response = my_client.get_bucket_encryption(Bucket=i)
                #print(response['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'])
                if response['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'] == 'AES256' : 
                    fh.write("%s,%s,%s,AES256,NA\n" % (acct['accountId'], acct['tenantId'],i))
                else :
                    fh.write("%s,%s,%s,KMS,%s\n" % (acct['accountId'], acct['tenantId'],i,response['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault'].get('KMSMasterKeyID')))
            except ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    if remediation.lower() == 'yes' : 
                        my_client.put_bucket_encryption(Bucket=i, ServerSideEncryptionConfiguration={ 'Rules': [ { 'ApplyServerSideEncryptionByDefault': { 'SSEAlgorithm': 'AES256' } } ] } )
                        fh.write("%s,%s,%s,AES256,Fixes\n" % (acct['accountId'], acct['tenantId'],i))
                    else :
                        fh.write("%s,%s,%s,NO,NA\n" % (acct['accountId'], acct['tenantId'],i))
                    RESULT['matchingResources']+=1
                    my_matches+=1
                else:
                    fh.write("%s,%s,%s,%s,Unknown\n" % (acct['accountId'], acct['tenantId'],i,e.response['Error']['Code']))
        return None, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s \n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey']))
        return None, fh

def Auto_Minor_Version_Upgrade_for_Replication_Instances_247(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="AutoMinorVersionUpgradeforReplicationInstances"
        RESULT['resourceName']="AutoMinorVersionUpgradeforReplicationInstances"
        (RESULT['outputFileName'],fh)=main.outfile('AutoMinorVersionUpgradeforReplicationInstances')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name = region
                    )
    else:
        my_session = boto3.Session(region_name = region)
    my_client = my_session.client('dms')
    fh.seek(0)
    if 'Region,AccountId,TenantId,Name,ReplicationInstanceIdentifier,AutoMinorVersionUpgrade\n' not in fh.readlines() :
        fh.write('Region,AccountId,TenantId,Name,ReplicationInstanceIdentifier,AutoMinorVersionUpgrade\n')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_response = my_client.describe_replication_instances()['ReplicationInstances']
        my_resources+=1
        RESULT['totalResources']+=1
        for k in my_response:
            ReplicationInstanceIdentifier = k['ReplicationInstanceIdentifier']
            AutoMinorVersionUpgrade = k['AutoMinorVersionUpgrade']
            if k['AutoMinorVersionUpgrade'] == False:
                fh.write("%s,%s,%s,%s,%s\n" % (region, acct['accountId'], acct['tenantId'],ReplicationInstanceIdentifier,AutoMinorVersionUpgrade))
                RESULT['matchingResources'] += 1
                my_matches += 1
        LOGFILE.write('Scanned %s  Replication Instance. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def Redshift_audit_logging_347(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="Redshift audit logging"
        RESULT['resourceName']="Redshift audit logging"
        (RESULT['outputFileName'],fh)=main.outfile('Redshift audit logging')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name = region
                    )
    else:
        my_session = boto3.Session(region_name = region)
    my_client = my_session.client('redshift')
    fh.seek(0)
    if 'Region,AccountId,TenantId,ClusterIdentifier,LoggingEnabled\n' not in fh.readlines() :
        fh.write('Region,AccountId,TenantId,ClusterIdentifier,LoggingEnabled\n')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_response = my_client.describe_clusters()['Clusters']
        my_resources+=1
        RESULT['totalResources']+=1
        for u in my_response:
            ClusterIdentifier = u['ClusterIdentifier']
            LoggingEnabled = my_client.describe_logging_status(ClusterIdentifier = ClusterIdentifier)['LoggingEnabled']
            if LoggingEnabled == False:
                fh.write("%s,%s,%s,%s,%s\n" % (region, acct['accountId'], acct['tenantId'],ClusterIdentifier,LoggingEnabled))
                my_matches += 1
                RESULT['matchingResources'] +=1
        LOGFILE.write('Scanned %s  redshift. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def Encryption_at_rest_for_ES_290(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="Encryption for ES Domains"
        RESULT['resourceName']="Encryption for ES Domains"
        (RESULT['outputFileName'],fh)=main.outfile('Encryption for ES Domains')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name = region
                    )
    else:
        my_session = boto3.Session(region_name = region)
    my_client = my_session.client('es')
    fh.seek(0)
    if 'Region,AccountId,TenantId,Domainname,Encryption\n' not in fh.readlines() :
        fh.write('Region,AccountId,TenantId,Domainname,Encryption\n')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_response = my_client.list_domain_names()['DomainNames']
        my_resources+=1
        RESULT['totalResources']+=1
        for k in my_response:
			Domains = k['DomainName']
			response = my_client.describe_elasticsearch_domains(DomainNames = [Domains])
			res = response['DomainStatusList']
			for u in res:
				Domainname = u['DomainName']
				Encryption = u['EncryptionAtRestOptions']['Enabled']
				if u['EncryptionAtRestOptions']['Enabled'] == False:
					fh.write("%s,%s,%s,%s,%s\n" % (region, acct['accountId'], acct['tenantId'],Domainname,Encryption))
					my_matches += 1
					RESULT['matchingResources'] +=1
        LOGFILE.write('Scanned %s  ES. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def Redshift_encryption_InTransit_102(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="disabled Redshift Intransit Encryption"
        RESULT['resourceName']="Redshift"
        (RESULT['outputFileName'],fh)=main.outfile('disabledRedshiftIntransitEncryption')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name = region
                    )
    else:
        my_session = boto3.Session(region_name = region)
    my_client = my_session.client('redshift')
    fh.seek(0)
    if 'Region,AccountId,TenantId,ClusterIdentifier,ParameterGroupName\n' not in fh.readlines() :
        fh.write('Region,AccountId,TenantId,ClusterIdentifier,ParameterGroupName\n')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_response = my_client.describe_clusters()['Clusters']
        for k in my_response:
    	    ClusterIdentifier = k['ClusterIdentifier']
            ParameterGroupName = k['ClusterParameterGroups'][0]['ParameterGroupName']
            response = my_client.describe_cluster_parameters(ParameterGroupName = ParameterGroupName)['Parameters']
            my_resources+=1
            RESULT['totalResources']+=1
            for u in response:
			    if u['ParameterName'] == 'require_ssl' and u['ParameterValue'] == 'false':
				    fh.write("%s,%s,%s,%s,%s\n" % (region, acct['accountId'], acct['tenantId'],ClusterIdentifier,ParameterGroupName))
				    my_matches += 1
				    RESULT['matchingResources'] +=1
        LOGFILE.write('Scanned %s  Redshift. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def list_bots(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="list bots"
        RESULT['resourceName']="list bots"
        (RESULT['outputFileName'],fh)=main.outfile('list bots')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name = "us-east-1"
                    )
    else:
        my_session = boto3.Session(region_name = 'us-east-1')
    my_client = my_session.client('lex-models')
    print (acct)
    fh.seek(0)
    if 'Region,AccountId,TenantId,Name\n' not in fh.readlines() :
        fh.write('Region,AccountId,TenantId,Name\n')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_response = my_client.get_bots()['bots']
        my_resources+=1
        RESULT['totalResources']+=1
        for k in my_response:
            Name = k['name']
            fh.write("%s,%s,%s,%s\n" % (region, acct['accountId'], acct['tenantId'],Name))
            RESULT['matchingResources'] += 1
            my_matches += 1
        LOGFILE.write('Scanned %s  EC2 SG . %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh


def classic_Loadbalancer_disabled_logging(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="Loadblanacer disabled logging"
        RESULT['resourceName']="Loadbalancer disabled logging"
        (RESULT['outputFileName'],fh)=main.outfile('Loadbalancer disabled logging')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name = region
                    )
    else:
        my_session = boto3.Session(region_name = region)
    my_client = my_session.client('elb')
    fh.seek(0)
    if 'Region,AccountId,TenantId,ClassicLoadBalancerName,LoggingEnabled\n' not in fh.readlines() :
        fh.write('Region,AccountId,TenantId,ClassicLoadBalancerName,LoggingEnabled\n')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_response = my_client.describe_load_balancers()['LoadBalancerDescriptions']
        for k in my_response:
            my_resources+=1
            RESULT['totalResources']+=1
            ClassicLoadBalancerName = k['LoadBalancerName']
            LoggingEnabled = my_client.describe_load_balancer_attributes(LoadBalancerName = ClassicLoadBalancerName)['LoadBalancerAttributes']['AccessLog']['Enabled']
            if LoggingEnabled == False:
			    fh.write("%s,%s,%s,%s,%s\n" % (region, acct['accountId'], acct['tenantId'],ClassicLoadBalancerName,LoggingEnabled))
			    my_matches += 1
			    RESULT['matchingResources'] +=1
        LOGFILE.write('Scanned %s  Load Balancer. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def Application_Loadbalancer_disabled_logging(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="Application Loadblanacer disabled logging"
        RESULT['resourceName']="Application Loadbalancer disabled logging"
        (RESULT['outputFileName'],fh)=main.outfile('Application Loadbalancer disabled logging')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name = region
                    )
    else:
        my_session = boto3.Session(region_name = region)
    my_client = my_session.client('elbv2')
    fh.seek(0)
    if 'Region,AccountId,TenantId,ApplicationLoadBalancerArn,LoadBalancerName\n' not in fh.readlines() :
        fh.write('Region,AccountId,TenantId,ApplicationLoadBalancerArn,LoadBalancerName\n')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_response = my_client.describe_load_balancers()['LoadBalancers']
        for k in my_response:
            my_resources+=1
            RESULT['totalResources']+=1
            ApplicationLoadBalancerArn = k['LoadBalancerArn']
            LoadBalancerName = k['LoadBalancerName']
            response = my_client.describe_load_balancer_attributes(LoadBalancerArn = ApplicationLoadBalancerArn)['Attributes'][0]
            if response['Key'] == 'access_logs.s3.enabled' and response['Value'] == 'true':
			    fh.write("%s,%s,%s,%s,%s\n" % (region, acct['accountId'], acct['tenantId'],ApplicationLoadBalancerArn,LoadBalancerName))
			    my_matches += 1
			    RESULT['matchingResources'] +=1
        LOGFILE.write('Scanned %s  Load Balancer. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh




AWS_SCANS = {
    "managed_policies_scan" : managed_policies_scan,
    "redshift_cluster_scan" : redshift_cluster_scan,
    "route53_domain_transfer_lock" : route53_domain_transfer_lock,
    "ebs_encryption_scan" : ebs_encryption_scan,
    "custom_policies_scan" : custom_policies_scan,
    "glacier_vault_scan" : glacier_vault_scan,
    "key_vault_scan" : key_vault_scan,
    "cloudfront_cert" : cloudfront_cert,
    "cloud_trail_check" : cloud_trail_check,
    "elasticsearch_domain_scan" : elasticsearch_domain_scan,
    "elastic_beanstalk_app_count" : elastic_beanstalk_app_count,
    "acm_cert_scan" : acm_cert_scan,
    "iam_cert_scan" : iam_cert_scan,
    "rds_instance_encryption_scan" : rds_instance_encryption_scan,
    "vpc_flow_logs" : vpc_flow_logs,
    "Guard_duty_enable_check" : Guard_duty_enable_check,
    "ebs_encryption_scan_2222" : ebs_encryption_scan_2222,
    "redshift_audit_logging" :redshift_audit_logging,
    "es_encryption" : es_encryption,
    "lb_list" : lb_list,
    "Inactive_user_335" : Inactive_user_335,
    "access_for_dms_replication_instances_246" : access_for_dms_replication_instances_246,
    "master_username_for_rds_316" : master_username_for_rds_316,
    "iam_roles_for_emrfs_requests_to_amazon_s3_228" : iam_roles_for_emrfs_requests_to_amazon_s3_228,
    "cloudwatch_log_group_retention_264" : cloudwatch_log_group_retention_264,
    "REDIS_AUTH_TOKEN_286" : REDIS_AUTH_TOKEN_286,
    "aws_service_role_for_config_332" : aws_service_role_for_config_332,
    "unencrypted_DMS_Endpoint_Connections_249" : unencrypted_DMS_Endpoint_Connections_249,
    "SNS_HTTPS_Subscription_320" : SNS_HTTPS_Subscription_320,
    "kinesis_Customer_Managed_Policy_112" : kinesis_Customer_Managed_Policy_112,
    "default_redshift_port_348" : default_redshift_port_348,
    "Enabling_Version_Upgrade_for_Redshift_346" : Enabling_Version_Upgrade_for_Redshift_346,
    "Encryption_for_Kinesis_113" : Encryption_for_Kinesis_113,
    "certified_DB_Engine_format" : certified_DB_Engine_format,
    "Default_SecurityGroup_for_replication_instance_must_not_be_used_248" : Default_SecurityGroup_for_replication_instance_must_not_be_used_248,
    "cyber_ark_IAM" : cyber_ark_IAM,
    "bucket_encryption_auto_remediation" : bucket_encryption_auto_remediation,
    "Auto_Minor_Version_Upgrade_for_Replication_Instances_247" : Auto_Minor_Version_Upgrade_for_Replication_Instances_247,
    "Redshift_audit_logging_347" : Redshift_audit_logging_347,
    "Encryption_at_rest_for_ES_290" : Encryption_at_rest_for_ES_290,
    "Redshift_encryption_InTransit_102" : Redshift_encryption_InTransit_102,
    "list_bots" : list_bots,
    "classic_Loadbalancer_disabled_logging" : classic_Loadbalancer_disabled_logging,
    "Application_Loadbalancer_disabled_logging" : Application_Loadbalancer_disabled_logging
}

AWS_SCANS_TYPE = {
    "redshift_cluster_scan" : "multi_region",
    "glacier_vault_scan" : "multi_region",
    "key_vault_scan" : "multi_region",
    "managed_policies_scan" : "single_region",
    "route53_domain_transfer_lock" : "single_region",
    "ebs_encryption_scan" : "multi_region",
    "custom_policies_scan" : "single_region",
    "cloudfront_cert" : "single_region",
    "cloud_trail_check" : "multi_region",
    "elasticsearch_domain_scan" : "multi_region",
    "elastic_beanstalk_app_count" : "multi_region",
    "acm_cert_scan" : "multi_region",
    "iam_cert_scan" : "single_region",
    "rds_instance_encryption_scan" : "multi_region",
    "vpc_flow_logs" : "multi_region",
    "Guard_duty_enable_check" : "multi_region",
    "ebs_encryption_scan_2222" : "multi_region",
    "redshift_audit_logging" : "multi_region",
    "es_encryption" : "multi_region",
    "lb_list" : "multi_region",
    "Inactive_user_335" : "single_region",
    "access_for_dms_replication_instances_246" : "multi_region",
    "master_username_for_rds_316" : "multi_region",
    "iam_roles_for_emrfs_requests_to_amazon_s3_228" : "multi_region",
    "cloudwatch_log_group_retention_264" : "multi_region",
    "REDIS_AUTH_TOKEN_286" : "multi_region",
    "aws_service_role_for_config_332" : "single_region",
    "unencrypted_DMS_Endpoint_Connections_249" : "multi_region",
    "SNS_HTTPS_Subscription_320" : "multi_region",
    "kinesis_Customer_Managed_Policy_112" : "single_region",
    "default_redshift_port_348" : "multi_region",
    "Enabling_Version_Upgrade_for_Redshift_346" : "multi_region",
    "Encryption_for_Kinesis_113" : "multi_region",
    "certified_DB_Engine_format" : "multi_region",
    "Default_SecurityGroup_for_replication_instance_must_not_be_used_248" : "multi_region",
    "cyber_ark_IAM" : "single_region",
    "bucket_encryption_auto_remediation" : "multi_region",
    "Auto_Minor_Version_Upgrade_for_Replication_Instances_247" : "multi_region",
    "Redshift_audit_logging_347" : "multi_region",
    "Encryption_at_rest_for_ES_290" : "multi_region",
    "Redshift_encryption_InTransit_102" : "multi_region",
    "list_bots" : "multi_region",
    "classic_Loadbalancer_disabled_logging" : "multi_region",
    "Application_Loadbalancer_disabled_logging" : "multi_region"
}