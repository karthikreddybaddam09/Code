import __main__ as main
import boto3
from botocore.client import ClientError
import json, time
import datetime

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



def active_root_key_scan(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="Root Key Access"
        RESULT['resourceName']="rootKeyAccess"
        (RESULT['outputFileName'],fh)=main.outfile('RootKeyAccess')
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
        my_gen_report = my_client.generate_credential_report()
        my_report = my_client.get_credential_report()
        my_csv =  my_report['Content']
        my_csv =  my_csv.split('\n')
        my_header = my_csv[0]
        my_header = my_header.split(',')
        key1_index = my_header.index('access_key_1_active')
        key2_index = my_header.index('access_key_2_active')
        my_resources+=1
        RESULT['totalResources']+=1
        position = fh.tell()
        fh.seek(0)
        if 'Region,tenantId,accountId,root key enabled\n' not in fh.readlines() :
            fh.write('Region,tenantId,accountId,root key enabled\n')
        for p in my_csv :
           p = p.split(',')
           if p[0] ==  '<root_account>' and ( p[key1_index].lower() == 'true' or p[key2_index].lower() == 'true' ) :
               #fh.write("Error : Root Access key(s) is active\n")
               fh.write('%s,%s,Yes\n' % (acct['tenantId'], acct['accountId']))
               RESULT['matchingResources'] += 1
               my_matches += 1
           elif p[0] ==  '<root_account>' and p[key1_index].lower() == 'true' and p[key2_index].lower() == 'false'  :
               fh.write("Root Access key(s) is in-active\n" )
               pass

        LOGFILE.write('Scanned %s root user. %s non-compliant.\n' % (my_resources, my_matches))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s \n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey']))
        return None, fh

def redshift_cluster_encryption_scan(acct, LOGFILE, region, fh=None):
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
        fh.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_details = my_client.describe_clusters()
        for a in my_details.get('Clusters'):
            try:
                my_resources+=1
                RESULT['totalResources']+=1
                if str(a.get('Encrypted')).lower() == 'true' :
                   fh.write("Redshift Cluster with name %s is safe of %s\n" % (a.get('ClusterIdentifier'), region))
                else :
                   fh.write("Error : Redshift Cluster with name %s is not safe of %s\n" % (a.get('ClusterIdentifier'), region) )
                   RESULT['matchingResources'] += 1
                   my_matches += 1

            except ClientError as e:
                fh.write("WARNING: Cannot see logs (%s) for Redshift cluster %s of %s\n" % (e.response['Error']['Code'], a.get('ClusterIdentifier'), region) )
        fh.write('Scanned %s Redshift cluster. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        fh.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def ec2_sg_scan_ck(ipv4_cidr, ipv6_cidr, guid_rule, to_port, from_port) :
    if ( to_port not in [80 , 443 ] and from_port not in [80 , 443 ] ) and ( ipv4_cidr == '0.0.0.0/0' or ipv6_cidr == '::/0' or guid_rule ) :
        return False
    else :
        return True

def safe_list_get(l, idx, default):
    try:
        return l[idx]
    except IndexError:
         return default

def ec2_sg_scan(acct, LOGFILE, region, fh=None, detailed=False):
    if not fh:
        RESULT['description']="EC2 SG"
        RESULT['resourceName']="ec2scan"
        (RESULT['outputFileName'],fh)=main.outfile('EC2Sg')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
        if detailed:
            fh.write('Region,TenantId,AccountId,VpcId,Groupname,Protocol,Fromport,Toport,Ipvradd,Ipv6add\n')
        else:
            fh.write('Region,TenantId,AccountId,VpcId,GroupName,Publicly Accessible\n')

    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name= region
                    )
    else:
        my_session = boto3.Session(region_name=region)
    my_client = my_session.client('ec2')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        position = fh.tell() 
        fh.seek(0)
        my_details = my_client.describe_security_groups()
        my_sg =  my_details.get('SecurityGroups')
        if 'Region,TenantId,AccountId,VpcId,Groupname,Protocol,Fromport,Toport,Ipvradd,Ipv6add\n' not in fh.readlines():
            if detailed:
                fh.write('Region,TenantId,AccountId,VpcId,Groupname,Protocol,Fromport,Toport,Ipvradd,Ipv6add\n')
            else:
                fh.write('Region,TenantId,AccountId,VpcId,GroupName,Publicly Accessible\n')
        for p in my_sg :
           my_resources+=1
           RESULT['totalResources']+=1
           ec2_sg_chk_sum = 0
           for i in p.get('IpPermissions') :
              to_port = i.get('ToPort')
              from_port = i.get('FromPort')
              ip_protocol = i.get('IpProtocol')
              ipv4_cidr = safe_list_get(i.get('IpRanges'), 0, {}).get('CidrIp')
              ipv6_cidr = safe_list_get(i.get('Ipv6Ranges'), 0, {}).get('CidrIpv6')
              guid_rule = safe_list_get(i.get('UserIdGroupPairs'), 0, {}).get('GroupId')
              ec2_sg_chk = ec2_sg_scan_ck(ipv4_cidr, ipv6_cidr, guid_rule, to_port, from_port)
              if ec2_sg_chk == False :
                ec2_sg_chk_sum += 1
                if detailed:
                    fh.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" % ( region, acct['tenantId'], acct['accountId'], p.get('VpcId'), p.get('GroupName'), ip_protocol, from_port, to_port, ipv4_cidr, ipv6_cidr  ) )
           if ec2_sg_chk_sum == 0 :
              #fh.write("SG %s in VPC %s is safe\n" % (p.get('GroupName'), p.get('VpcId')) )
              pass
           else :
              #fh.write("Error : SG %s in VPC %s is unsafe\n" % (p.get('GroupName'), p.get('VpcId')) )
              if not detailed:
                  fh.write("%s,%s,%s,%s,%s,%s,%s,YES\n" % ( region, acct['tenantId'], acct['accountId'], p.get('VpcId'), p.get('GroupName'), from_port, to_port ) )
              RESULT['matchingResources'] += 1
              my_matches += 1

        LOGFILE.write('Scanned %s EC2 SGs. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def ec2_sg_scan_detailed(acct, LOGFILE, region, fh=None):
    return ec2_sg_scan(acct, LOGFILE, region, fh, True)

def ec2_default_sg_scan(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="EC2 Default SG Scan"
        RESULT['resourceName']="ec2DefaultSGScan"
        (RESULT['outputFileName'],fh)=main.outfile('EC2DefaultSg')
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
        if 'Region,TenantId,AccountId,VpcID,InstanceID,Using Default SG\n' not in fh.readlines() :
            fh.write('Region,TenantId,AccountId,VpcID,InstanceID,Using Default SG\n')
        try :
            my_response = my_client.describe_instances()
            for p in my_response['Reservations']:
                Instances = p['Instances']
                for i in Instances:
                    my_resources+=1
                    RESULT['totalResources']+=1
                    print(i.get('InstanceId'))
                    for sg in i.get('SecurityGroups') :
                       if (sg.get('GroupName')).lower() == 'default' :
                              RESULT['matchingResources']+=1
                              my_matches+=1
                              fh.write("%s,%s,%s,%s,%s,Yes\n" % ( region, acct['tenantId'], acct['accountId'], i.get('VpcId'), i.get('InstanceId') ) )
        except ClientError as e:
            LOGFILE.write("WARNING: Cannot describe EC2 for default SG %s of %s\n" % (e.response['Error']['Code'], region ) )
        LOGFILE.write('Scanned %s instances. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh


def lb_log_enabled_scan(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="LB Log Enabled"
        RESULT['resourceName']="lb_log_enabled"
        (RESULT['outputFileName'],fh)=main.outfile('LBLogEnabled')
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
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_details = my_client.describe_load_balancers()
        my_details2 = my_client2.describe_load_balancers()
        position = fh.tell() 
        fh.seek(0)
        if 'Region,AccountId,TenantId,VpcId,LoadBalancerName,Type,Log Enabled\n' not in fh.readlines() :
            fh.write('Region,AccountId,TenantId,VpcId,LoadBalancerName,Type,Log Enabled\n')
        for a in my_details.get('LoadBalancers'):
            try:
                my_resources+=1
                RESULT['totalResources']+=1
                response_raw = my_client.describe_load_balancer_attributes(LoadBalancerArn=a.get('LoadBalancerArn'))
                response = response_raw.get('Attributes')
                chk_count = 0
                for attr in response :
                   if attr.get('Key') == 'access_logs.s3.enabled' and attr.get('Value') != 'true' :
                      chk_count += 1    
                if chk_count == 0 :
                   #fh.write("Access log enabled on ALB with name %s in vpc - %s of %s\n" % (a.get('LoadBalancerName'), a.get('VpcId'), region))
                   pass
                else :
                   #fh.write("Error : Access log not enabled on ALB with name %s in vpc - %s of %s\n" % (a.get('LoadBalancerName'), a.get('VpcId'), region) )
                   fh.write("%s,%s,%s,%s,%s,ALB,No" % (region, acct['accountId'], acct['tenantId'], a.get('VpcId'), a.get('LoadBalancerName') ))
                   RESULT['matchingResources'] += 1
                   my_matches += 1

            except ClientError as e:
                LOGFILE.write("WARNING: Cannot see logs (%s) for ALB SSL Policy %s of %s\n" % (e.response['Error']['Code'], a.get('LoadBalancerArn'), region) )

        for a in my_details2.get('LoadBalancerDescriptions'):
            try:
                my_resources+=1
                RESULT['totalResources']+=1
                response_raw2 = my_client2.describe_load_balancer_attributes(LoadBalancerName=a.get('LoadBalancerName'))
                response2 = response_raw2.get('LoadBalancerAttributes').get('AccessLog').get('Enabled')
                if str(response2).lower() == 'true' :
                   #fh.write("Access log enabled on ELB with name %s in vpc - %s of %s\n" % (a.get('LoadBalancerName'), a.get('VPCId'), region))
                   pass
                else :
                   #fh.write("Error : Access log not enabled on ELB with name %s in vpc - %s of %s\n" % (a.get('LoadBalancerName'), a.get('VPCId'), region) )
                   fh.write("%s,%s,%s,%s,%s,ELB,No" % (region, acct['accountId'], acct['tenantId'], a.get('VpcId'), a.get('LoadBalancerName') ))
                   RESULT['matchingResources'] += 1
                   my_matches += 1
            except ClientError as e:
                LOGFILE.write("WARNING: Cannot see logs (%s) for ELB Access logs %s of %s\n" % (e.response['Error']['Code'], a.get('LoadBalancerName'), region) )
        LOGFILE.write('Scanned %s ALB. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def lb_ssl_policy_scan(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="LB Security Policy"
        RESULT['resourceName']="lb_security_policy"
        (RESULT['outputFileName'],fh)=main.outfile('LBSecurityPolicy')
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
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_details = my_client.describe_load_balancers()
        my_details2 = my_client2.describe_load_balancers()
        ssl_policy_list = ['ELBSecurityPolicy-2016-08', 'ELBSecurityPolicy-TLS-1-2-2017-01', 'ELBSecurityPolicy-TLS-1-1-2017-01', 'ELBSecurityPolicy-TLS-1-2-2017-01']
        position = fh.tell()
        fh.seek(0)
        if 'Region,AccountId,TenantId,VpcId,LoadBalancerName,Type,Safe\n' not in fh.readlines() :
            fh.write('Region,AccountId,TenantId,VpcId,LoadBalancerName,Type,Safe\n')
        for a in my_details.get('LoadBalancers'):
            try:
                my_resources+=1
                RESULT['totalResources']+=1
                response_raw = my_client.describe_listeners(LoadBalancerArn=a.get('LoadBalancerArn'))
                response = response_raw.get('Listeners')
                chk_count = 0
                for listener in response:
                   ssl_p = listener.get('SslPolicy')
                   if ssl_p not in ssl_policy_list :
                      chk_count += 1
                if chk_count == 0 :
                   #fh.write("ALB with name %s in vpc - %s is safe of %s\n" % (a.get('LoadBalancerName'), a.get('VpcId'), region))
                   pass
                else :
                   #fh.write("Error : ALB with name %s in vpc - %s is not safe of %s\n" % (a.get('LoadBalancerName'), a.get('VpcId'), region) )
                   fh.write("%s,%s,%s,%s,%s,ALB,No" % (region, acct['accountId'], acct['tenantId'], a.get('VpcId'), a.get('LoadBalancerName') ))
                   RESULT['matchingResources'] += 1
                   my_matches += 1

            except ClientError as e:
                LOGFILE.write("WARNING: Cannot see logs (%s) for ALB SSL Policy %s of %s\n" % (e.response['Error']['Code'], a.get('LoadBalancerArn'), region) )

        for a in my_details2.get('LoadBalancerDescriptions'):
            try:
                my_resources+=1
                RESULT['totalResources']+=1
                response_raw2 = my_client2.describe_load_balancer_policies(LoadBalancerName=a.get('LoadBalancerName'))
                response2 = response_raw2.get('PolicyDescriptions')
                chk_count = 0
                for p in response2 :
                  for attr in p.get('PolicyAttributeDescriptions') :
                     ssl_n = attr.get('AttributeName')
                     ssl_v = attr.get('AttributeValue')
                     if ssl_n == 'Reference-Security-Policy' and ssl_v not in ssl_policy_list :
                        chk_count += 1
                if chk_count == 0 :
                   #fh.write("ELB with name %s in vpc - %s is safe of %s\n" % (a.get('LoadBalancerName'), a.get('VPCId'), region))
                   pass
                else :
                   #fh.write("Error : ELB with name %s in vpc - %s is not safe of %s\n" % (a.get('LoadBalancerName'), a.get('VPCId'), region) )
                   fh.write("%s,%s,%s,%s,%s,ELB,No" % (region, acct['accountId'], acct['tenantId'], a.get('VpcId'), a.get('LoadBalancerName') ))
                   RESULT['matchingResources'] += 1
                   my_matches += 1




            except ClientError as e:
                LOGFILE.write("WARNING: Cannot see logs (%s) for ELB SSL Policy %s of %s\n" % (e.response['Error']['Code'], a.get('LoadBalancerName'), region) )
        LOGFILE.write('Scanned %s ALB. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def default_vpc_scan(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="Default VPC Scan"
        RESULT['resourceName']="DefaultVPCScan"
        (RESULT['outputFileName'],fh)=main.outfile('DefaultVPCScan')
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
        LOGFILE.write("Scanning Account %s for Tenant %s of %s \n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        fh.seek(0)
        if 'Region,TenantId,AccountId,VpcID(Default),IPused\n' not in fh.readlines() :
            fh.write('Region,TenantId,AccountId,VpcID(Default),IPused\n')
        try :
            my_response = my_client.describe_vpcs()
            for p in my_response.get('Vpcs'):
                default_chk = p.get('IsDefault')
                vpc = p.get('VpcId')
                if default_chk == True :
                    my_r = my_client.describe_subnets(Filters=[{ 'Name' : 'vpc-id', 'Values' : [vpc] }])
                    my_resources+=1
                    RESULT['totalResources']+=1
                    used_ip_total = 0
                    for i in my_r.get('Subnets'):
                         ip_ava_now = i.get('AvailableIpAddressCount')
                         host_bits = 32 - int(i.get('CidrBlock').split('/')[-1])
                         ip_ava = 2**host_bits - 5 
                         if ip_ava_now < ip_ava :
                            used_ip = ip_ava - ip_ava_now
                            used_ip_total = used_ip_total + used_ip

                    if used_ip_total > 0 :
                         RESULT['matchingResources']+=1
                         my_matches+=1
                         fh.write("%s,%s,%s,%s,%s\n" % ( region, acct['tenantId'], acct['accountId'], p.get('VpcId'), used_ip_total ) )
        except ClientError as e:
            LOGFILE.write("WARNING: Cannot describe default VPC %s of %s\n" % (e.response['Error']['Code'], region ) )
        LOGFILE.write('Scanned %s vpc. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def s3_default_encryption(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="S3 Bucket Default Encryption"
        RESULT['resourceName']="S3BucketDefaultEncryption"
        (RESULT['outputFileName'],fh)=main.outfile('S3BucketDefaultEncryption')
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
        my_client = my_session.client('s3')
        LOGFILE.write("Scanning Account %s for Tenant %s\n" % (acct['accountId'], acct['tenantId']))
        my_resources=0
        my_matches=0
        fh.seek(0)
        if 'TenantId,AccountId,Bucket,Default encryption enabled\n' not in fh.readlines() :
            fh.write('TenantId,AccountId,Bucket,Default encryption enabled\n')
        try :
            my_response = my_client.list_buckets()
            for b in my_response['Buckets']:
                try:
                  my_resources+=1
                  RESULT['totalResources']+=1
                  my_details = my_client.get_bucket_encryption(
                      Bucket=b['Name']
                  )
                  if 'ServerSideEncryptionConfiguration' in my_details.keys():
                      #fh.write("Default encryption is enabled on bucket %s\n" % (b['Name']))
                      pass
                  else:
                      RESULT['matchingResources']+=1
                      my_matches+=1
                      fh.write("%s,%s,%s,No\n" % (acct['tenantId'], acct['accountId'], b['Name'] ))
                except ClientError as e:
                  if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                      print(e.response['Error']['Code'])
                      RESULT['matchingResources']+=1
                      my_matches+=1
                      fh.write("%s,%s,%s,No\n" % (acct['tenantId'], acct['accountId'], b['Name'] ))
                  else:
                      print(e.response['Error']['Code'])
                      print(str(e))
                      fh.write("%s,%s,%s,Unknown\n" % (acct['tenantId'], acct['accountId'], b['Name'] ))
            return RESULT, fh
        except ClientError as e:
            LOGFILE.write("WARNING: Cannot s3 bucket for default encryption %s\n" % (e.response['Error']['Code'] ) )
        LOGFILE.write('Scanned %s volumns. %s non-compliant.\n' % (my_resources, my_matches))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def sg_scan(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="Security Group Scan"
        RESULT['resourceName']="SecurityGroupScan"
        (RESULT['outputFileName'],fh)=main.outfile('Security_Group_Scan')
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
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        my_details = my_client.describe_security_groups()
        my_sg =  my_details.get('SecurityGroups')
        position = fh.tell()
        fh.seek(0)
        if 'Region,tenantId,accountId,VpcId,GroupId,Default SG has rules\n' not in fh.readlines() :
            fh.write('Region,tenantId,accountId,VpcId,GroupId,Default SG has rules\n')
        for p in my_sg :
           if p.get('GroupName') == 'default' :
               my_resources+=1
               RESULT['totalResources']+=1
               for a in p.get('IpPermissions') :
                if not a.get('IpRanges') == []:
                  fh.write("%s,%s,%s,%s,%s,Yes\n" % ( region, acct['tenantId'], acct['accountId'], p.get('VpcId'), p.get('GroupId')) )
                  RESULT['matchingResources'] += 1
                  my_matches += 1

        LOGFILE.write('Scanned %s EC2 SGs. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def acm_cert_scan(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="ACM Cert Scan"
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
        my_response_acm_list = my_client_acm.list_certificates(Includes={'keyTypes':['RSA_2048']})
        
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
        if 'TenantId,AccountId,CertName,Arn,CertId,Status,Path,Issuer,Type,Source,NotAfter,DaysToExpire\n' not in fh.readlines() :
            fh.write('TenantId,AccountId,CertName,Arn,CertId,Status,Path,Issuer,Type,Source,NotAfter,DaysToExpire\n')
        for a in my_response_iam_list['ServerCertificateMetadataList'] :
            my_resources+=1
            RESULT['totalResources']+=1
            c_name = a.get('ServerCertificateName')
            c_id = a.get('ServerCertificateId')
            c_arn = a.get('Arn')
            c_path = a.get('Path')
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
                 fh.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%d\n" % ( acct['tenantId'], acct['accountId'], c_name, c_arn, c_id, c_status, c_path, c_issuer, c_type, c_source, exp_date, remaining.days ) )
            else :
               RESULT['matchingResources'] += 1
               my_matches += 1
               fh.write("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,Unknown,Unknown\n" % ( acct['tenantId'], acct['accountId'], c_name, c_arn, c_id, c_status, c_path, c_issuer, c_type, c_source ) ) 
        LOGFILE.write('Scanned %s instances. %s non-compliant.\n' % (my_resources, my_matches))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey']))
        return None, fh

def sso_check(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="Sso Scan"
        RESULT['resourceName']="Sso_scan"
        (RESULT['outputFileName'],fh)=main.outfile('Sso')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey']
                    )
    else:
        my_session = boto3.Session()
    my_client = my_session.client('ds')
    try:
        fh.write("Scanning Account %s for Tenant %s \n" % (acct['accountId'], acct['tenantId']))
        my_resources=0
        my_matches=0
        my_details = my_client.describe_directories()
        try:
        #if my_details["DirectoryDescriptions"]:
          for a in my_details["DirectoryDescriptions"]:
              try:
                  my_resources+=1
                  RESULT['totalResources']+=1
                  if str(a.get('SsoEnabled')) == 'True' :
                    fh.write("SSO is enabled for account %s\n" % (acct['accountId']))
                  else :
                    fh.write("Error : SSO is not enabled for account %s\n" % (acct['accountId']) )
                    RESULT['matchingResources'] += 1
                    my_matches += 1
              except ClientError as e:
                  fh.write("WARNING: Cannot see logs (%s) for Directory\n" % (e.response['Error']['Code']) )
        except ClientError as e:
            LOGFILE.write("WARNING:  %s\n" % (e.response['Error']['Code'] ) )
        fh.write('Scanned %s Directories. %s non-compliant.\n' % (my_resources, my_matches))
        fh.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s \n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey']))
        return None, fh

def unencrypted_rds_db_snapshot_scan(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="Unencrypted RDS Snapshots"
        RESULT['resourceName']="Unencrypted rds_snapshots"
        (RESULT['outputFileName'],fh)=main.outfile('UnencryptedRDSSnapshots')
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
        fh.seek(0)
        if 'TenantId,AccountId,Rds_Snapshot,Region,EngineType,Encryption enabled\n' not in fh.readlines() :
            fh.write('TenantId,AccountId,Rds_Snapshot,Region,EngineType,Encryption enabled\n')
        my_details = my_client.describe_db_snapshots()
        for a in my_details.get('DBSnapshots'):
            try:
                my_resources+=1
                RESULT['totalResources']+=1
                if str(a.get('Encrypted')).lower() == 'true' :
                    #fh.write("%s,%s,%s,%S,No\n" % (acct['tenantId'], acct['accountId'], a.get('DBSnapshotIdentifier'), region))
                    pass
                else:
                    my_matches += 1
                    RESULT['matchingResources']+=1
                    fh.write("%s,%s,%s,%s,%s,No\n" % (acct['tenantId'], acct['accountId'], a.get('DBSnapshotIdentifier'), region, a.get('Engine')))

            except ClientError as e:
                LOGFILE.write("WARNING: Cannot see logs (%s) for RDS Snapshots %s of %s\n" % (e.response['Error']['Code'], a.get('DBSnapshotIdentifier'), region) )
        LOGFILE.write('Scanned %s RDS Snapshots. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'],region))
        return None, fh

def dynamodb_encryption_scan(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="Dynamodb_encryption scan"
        RESULT['resourceName']="Dynamodb_encryption scan"
        (RESULT['outputFileName'],fh)=main.outfile('Dynamodb_encryption')
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
    my_client = my_session.client('dynamodb')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        fh.seek(0)
        if 'TenantId,AccountId,Tablename,Encryption enabled\n' not in fh.readlines() :
            fh.write('TenantId,AccountId,Tablename,Encryption enabled\n')
        my_details = my_client.list_tables()

        for a in my_details.get('TableNames'): 
            try:
                my_resources+=1
                RESULT['totalResources']+=1
                resp = my_client.describe_table(TableName='a')
                if str(resp.get('Table').get('SSEDescription').get('Status')).lower() == 'disabled' :
                    #fh.write("%s,%s,%s,%S,No\n" % (acct['tenantId'], acct['accountId'], a.get('DBSnapshotIdentifier'), region))
                    pass
                else:
                    my_matches += 1
                    RESULT['matchingResources']+=1
                    fh.write("%s,%s,%s,No\n" % (acct['tenantId'], acct['accountId'], a.get('TableNames')))
            except ClientError as e:
                LOGFILE.write("WARNING: Cannot see logs (%s) \n" % (e.response['Error']['Code'] ))
        LOGFILE.write('Scanned %s RDS Snapshots. %s non-compliant.\n' % (my_resources, my_matches))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey']))
        return None, fh


def get_master_members(master_client, detector_id):
    member_dict = {}
    paginator = master_client.get_paginator('list_members')
    operation_parameters = {
        'DetectorId': detector_id,
        'OnlyAssociated': 'false'
    }

    page_iterator = paginator.paginate(**operation_parameters)

    for page in page_iterator:
        if page['Members']:
            for member in page['Members']:
                member_dict.update({member['AccountId']: member['RelationshipStatus']})

    return member_dict

#remediation tool
def guardDuty_scan(acct, LOGFILE, region, fh=None):
    file_name = '../gaurdduty.csv'
    account = acct['accountId']
    try :
        with open(file_name) as f :
            account_list = f.read()
            account_list = account_list.split()
    except :
        print("ERROR : Unable to open file %s" % (file_name))
        return None, fh
    remediation = "no"
    aws_account_dict = {}
    aws_master_account_dict = {}
    for a in account_list :
        split_line = a.split(",")
        if len(split_line) == 3:
            aws_account_dict[split_line[1]] = split_line[2]
            aws_master_account_dict[split_line[1]] = split_line[0]
        else :    
            print("ERROR : Unable to process line: %s" % ( a ))
            

    if account not in aws_account_dict.keys() :
        print("ERROR : Account %s not present in input-file %s" % (account , file_name) )
        return RESULT, fh
        
    
    else :
        master_account_id=aws_master_account_dict[account]
 
    gd_invite_message = "Account %s invites you to join GuardDuty." % (master_account_id)

    if not fh:
        RESULT['description']="GuardDuty check"
        RESULT['resourceName']="GuardDutyCheck"
        (RESULT['outputFileName'],fh)=main.outfile('GuardDutyCheck')
        RESULT['matchingResources']=0
        RESULT['totalResources']=0
    if 'secretKey' in acct.keys():
        my_session = boto3.Session(
                    aws_access_key_id=acct['accessKey'],
                    aws_secret_access_key=acct['secretKey'],
                    region_name=region
                    )
    else:
        print("ERROR : This function can not be executed locally." )
        return RESULT, fh
        

    my_resources=0
    my_matches=0
    try :
        #account = acct['accountId']
        master_session = boto3.Session(region_name=region)
        master_client = master_session.client('guardduty')
        master_detector_id =  master_client.list_detectors()['DetectorIds']
        if not master_detector_id : master_detector_id = master_client.create_detector(Enable=True)['DetectorId']
        master_detector_id = master_detector_id[0]
        member_dict = get_master_members(master_client, master_detector_id)
        my_client = my_session.client('guardduty')
        detectors_list =  my_client.list_detectors()['DetectorIds']                 
        if not detectors_list : 
            detectors_list = my_client.create_detector(Enable=True)['DetectorId']
            time.sleep(5)
        detectors_list =  my_client.list_detectors()['DetectorIds']
        detectors_list = detectors_list[0]
       
        # Check if a member account is already associated to a Master account
        # Deassociate it from master account so that it can accept new invitation
        response = my_client.get_master_account(DetectorId=detectors_list)

        if 'Master' in response:  
            if response['Master'] and remediation.lower() == 'yes':
                if response['Master']['AccountId'] != master_account_id:
                    print("Member account is associated to a master account. Deassociating....")
                    output = my_client.disassociate_from_master_account(DetectorId=detectors_list)
                    print("Member has been disassociated from Master.")
                    inv = my_client.list_invitations()
                    master_id = inv['Invitations'][0]['AccountId']
                    print("Master account ID is: %s" % (master_id))
                    my_client.decline_invitations(AccountIds=[master_id])
                    my_client.delete_invitations(AccountIds=[master_id])
                    print("Invite has been decline.")
        else:
            response = my_client.list_invitations()
                
            if response['Invitations']:
                for account in response['Invitations']:
                    if account['AccountId'] != "322357363877":
                        account_id = account['AccountId']
                        my_client.decline_invitations(AccountIds=[account_id])
                        my_client.delete_invitations(AccountIds=[account_id])
    
        
   
        if account not in member_dict:
            my_resources+=1
            RESULT['totalResources']+=1
            if remediation.lower() == 'yes': 
                master_client.create_members(AccountDetails=[{'AccountId': account,'Email': aws_account_dict[account]}],DetectorId=master_detector_id)
                print('INFO : REMEDIATION : Added account %s to member list in GuardDuty master account for region %s' % (account, region))
            else :
                print('WARNING : Not adding account %s to member list in GuardDuty master account for region %s' % (account, region))
        else :
            print('INFO : Account %s is already a member of GuardDuty master account for region %s' % (account, region))
        
        if member_dict.get(account) == 'EmailVerificationFailed':
            # Member is enabled and already being monitored
            print('ERROR : Account %s failed because of email verification' % (account))
            if remediation.lower() == 'yes': 
                master_client.disassociate_members(AccountIds=[account],DetectorId=master_detector_id)
                master_client.delete_members(AccountIds=[account], DetectorId=master_detector_id)
                print('INFO : REMEDIATION : Deleting members for %s in %s' % (account, region))
                master_client.create_members(AccountDetails=[{'AccountId': account, 'Email': aws_account_dict[account]}], DetectorId=master_detector_id)
                print('INFO : REMEDIATION : Added account %s to member list in GuardDuty master account for region %s' % (account, region))
                fh.write('INFO : REMEDIATION : Added account %s to member list in GuardDuty master account for region %s\n' % (account, region))

        if member_dict.get(account) == 'Enabled':
            # Member is enabled and already being monitored
            print('INFO : Account %s is already enabled' % (account))
        else :
            if member_dict.get(account) == 'Disabled' :
                # Member was disabled
                print('INFO : Account %s is member but disabled' % (account))
                if remediation.lower() == 'yes': 
                    master_client.start_monitoring_members(AccountIds=[account],DetectorId=master_detector_id)
                    print('INFO : REMEDIATION : Account %s Re-Enabled' % (account))
                

            if remediation.lower() == 'yes':
                count = 0 
                
                while member_dict.get(account) != 'Enabled' :
                    time.sleep(10)
                    count = count + 1
                    if member_dict.get(account) == 'Created' :
                        # Member has been created in the GuardDuty master account but not invited yet
                        master_client.invite_members(AccountIds=[account], DetectorId=master_detector_id, DisableEmailNotification=True, Message=gd_invite_message)
                        print('INFO : Invited Account %s to GuardDuty master account in region %s' % (account, region))
                        fh.write('INFO : Invited Account %s to GuardDuty master account in region %s\n' % (account, region))
                        print("Outside IF VALUE OF ACCOUNT STATUS: ",member_dict.get(account))
                        
                    if member_dict.get(account) == 'Invited' or member_dict.get(account) == 'Resigned' :
                        print("Inside IF VALUE OF ACCOUNT STATUS: ",member_dict.get(account))
                        # member has been invited so accept the invite
                        response = my_client.list_invitations()
                        invitation_dict = {}
                        invitation_id = None
                        for invitation in response['Invitations']:
                            invitation_id = invitation['InvitationId']


                        if invitation_id is not None:
                            my_client.accept_invitation(DetectorId=detectors_list, InvitationId=invitation_id, MasterId=str(master_account_id) )
                            print('INFO Accepting Account %s to GuardDuty master account in region %s' % (account, region))
                            fh.write('INFO Accepting Account %s to GuardDuty master account in region %s\n' % (account, region))

                        # Refresh the member dictionary
                    member_dict = get_master_members(master_client, master_detector_id)
                    if member_dict.get(account) == 'EmailVerificationFailed' and count > 3 : 
                        print("ERROR : Unable to accept email invite for member account %s in region %s" % (account, region))
                        break

        
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s \n" % (e.response['Error']['Code'],acct.get('tenantId'),acct.get('accountId'),acct.get('accessKey')))
        return None, fh

def check_for_cloud_trail_enabled(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="CloudTrail Policy Enable"
        RESULT['resourceName']="CloudTrailPolicyEnable"
        (RESULT['outputFileName'],fh)=main.outfile('CloudTrailPolicyEnable')
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
        if 'Region,TenantId,AccountId,Trail\n' not in fh.readlines() :
            fh.write('Region,TenantId,AccountId,Trail\n')
        try :
            my_response = my_client.describe_trails(trailNameList=[])
            cloudtrail_status = ""
            if not my_response['trailList']:
                cloudtrail_status = 'NO'
                #fh.write("%s,%s,%s,%s\n" % ( region, acct['tenantId'], acct['accountId'], cloudtrail_status ) )
            else:
                cloudtrail_status = 'YES'
                RESULT['matchingResources']+=1
                my_matches+=1
                fh.write("%s,%s,%s,%s\n" % ( region, acct['tenantId'], acct['accountId'], cloudtrail_status ) )
        except ClientError as e:
            LOGFILE.write("WARNING: Cannot describe cloud trail, error %s of %s\n" % (e.response['Error']['Code'], region ) )
        LOGFILE.write('Scanned %s cloud trail. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh


def Guard_duty_master_acount_check(acct, LOGFILE, region, fh=None):
    '''
    This function is to identify the master account ID of any tenant. 
    '''
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
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        fh.seek(0)
        if 'Region,TenantId,AccountId,MasterAccount_Status,MasterAccountID\n' not in fh.readlines() :
            fh.write('Region,TenantId,AccountId,MasterAccount_Status,MasterAccountID\n')
        my_resources+=1
        RESULT['totalResources']+=1
        #value = response['DetectorIds']
        try :
            my_response = my_client.list_detectors()
            MasterAccount_Status = ""
            if my_response['DetectorIds']:
                try:
                    response = my_client.get_master_account(DetectorId=my_response['DetectorIds'][0])
                    if response['Master']:
                        MasterAccount_Status  = 'YES'
                        RESULT['matchingResources']+=1
                        my_matches+=1
                        fh.write("%s,%s,%s,%s,%s\n" % ( region, acct['tenantId'], acct['accountId'], MasterAccount_Status, response['Master']['AccountId'] ) )
                except ClientError as e:
                        print(e)

        except ClientError as e:
            LOGFILE.write("WARNING: Cannot list guardduty, error %s of %s\n" % (e.response['Error']['Code'], region ) )
        LOGFILE.write('Scanned %s cloud trail. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh

def get_tenant_ids(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="tenant ids"
        RESULT['resourceName']="tenant_ids"
        (RESULT['outputFileName'],fh)=main.outfile('tenant')
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
        #my_client = my_session.client('cloudtrail')
        #LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        #y_resources=0
        #my_matches=0
        fh.seek(0)
        if 'TenantId,AccountId\n' not in fh.readlines() :
            fh.write('TenantId,AccountId\n')
     
        fh.write("%s,%s\n" % (acct['tenantId'], acct['accountId']) )
        #LOGFILE.write('Scanned %s. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'], region))
        return None, fh


def unencrypted_elasticache_redis(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="Unencrypted Elasticache"
        RESULT['resourceName']="Unencrypted Elasticache"
        (RESULT['outputFileName'],fh)=main.outfile('UnencryptedElasticaches')
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
    my_client = my_session.client('elasticache')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        fh.seek(0) 
        if 'Region,TenantId,AccountId,ReplicationGroupId,TransitEncryptionEnabled,AtRestEncryptionEnabled\n' not in fh.readlines() :
            fh.write('Region,TenantId,AccountId,ReplicationGroupId,TransitEncryptionEnabled,AtRestEncryptionEnabled\n')
        my_cache_details = my_client.describe_cache_clusters()
        replicationid = []
        for nodes in my_cache_details['CacheClusters']:
            if str(nodes.get('Engine')) == 'redis':
                RGroupId = nodes.get('ReplicationGroupId')
                #eng = nodes.get('engine')
                replicationid.append(RGroupId)
        RepGroupId = set(replicationid)
        RepGroupId = filter(None,RepGroupId)
        #print(RepGroupId)
        for value in RepGroupId:
            response = my_client.describe_replication_groups(ReplicationGroupId = value)['ReplicationGroups'][0]
            try: 
                encryptionrest = response.get('AtRestEncryptionEnabled')
                encryptiontransit = response.get('TransitEncryptionEnabled')
                my_resources+=1
                RESULT['totalResources']+=1
                if str(encryptionrest).lower() == 'true' and str(encryptiontransit).lower() == 'true':
                    pass
                else:
                    fh.write("%s,%s,%s,%s,%s,%s\n" % (region, acct['tenantId'], acct['accountId'],value,encryptionrest,encryptiontransit) )
                    RESULT['matchingResources'] += 1
                    my_matches += 1

            except ClientError as e:
                LOGFILE.write("WARNING: Cannot check cache instance encryption (%s) for cache  %s of %s\n" % (e.response['Error']['Code'], b, region) )

        LOGFILE.write('Scanned %s  cache cluster. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'],region))
        return None, fh

def elasticache_default_port(acct, LOGFILE, region, fh=None):
    if not fh:
        RESULT['description']="Elasticache Default Ports"
        RESULT['resourceName']="Elasticache Default Ports"
        (RESULT['outputFileName'],fh)=main.outfile('ElasticacheDefaultPorts')
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
    my_client = my_session.client('elasticache')
    try:
        LOGFILE.write("Scanning Account %s for Tenant %s of %s\n" % (acct['accountId'], acct['tenantId'], region))
        my_resources=0
        my_matches=0
        fh.seek(0)
        if 'Region,TenantId,AccountId,ReplicationGroupId,Node,DefaultPort\n' not in fh.readlines() :
            fh.write('Region,TenantId,AccountId,ReplicationGroupId,Node,DefaultPort\n')
        my_cache_details = my_client.describe_cache_clusters(ShowCacheNodeInfo=True)
        for nodes in my_cache_details['CacheClusters']:
            # We will go to each node and check port number 
            try:
                if str(nodes.get('Engine')) == 'redis':
                    redisport = nodes['CacheNodes'][0]['Endpoint']['Port']
                    #a = nodes['CacheNodes'][0]
                    #b = a.get('Endpoint')
                    #redisport = b.get('Port')
                    if redisport == 6379:
                        fh.write("%s,%s,%s,%s,%s,%s\n" % (region, acct['tenantId'], acct['accountId'],nodes.get('ReplicationGroupId'),nodes.get('CacheClusterId'),redisport))
                        RESULT['matchingResources'] += 1
                        my_matches += 1
                elif str(nodes.get('Engine')) == 'memcached':
                    memcachedport = nodes['ConfigurationEndpoint']['Port']
                    #memcachedport = c.get('Port')
                    if memcachedport == 11211:
                        fh.write("%s,%s,%s,memcached,%s,%s\n" % (region, acct['tenantId'], acct['accountId'],nodes.get('CacheClusterId'),memcachedport))
                        RESULT['matchingResources'] += 1
                        my_matches += 1
            except ClientError as e:
                LOGFILE.write("WARNING: Cannot check elastic cache instance port (%s) for cache  %s of %s\n" % (e.response['Error']['Code'], b, region))
        LOGFILE.write('Scanned %s  cache cluster. %s non-compliant of %s.\n' % (my_resources, my_matches, region))
        LOGFILE.write('--------------------\n')
        return RESULT, fh
    except ClientError as e:
        LOGFILE.write("%s with for tenant %s and Account %s with AccessKey: %s of %s\n" % (e.response['Error']['Code'],acct['tenantId'],acct['accountId'],acct['accessKey'],region))
        return None, fh

AWS_SCANS = {
    "redshift_cluster_encryption_scan" : redshift_cluster_encryption_scan,
    "ec2_sg_scan" : ec2_sg_scan,
    "ec2_sg_scan_detailed" : ec2_sg_scan_detailed,
    #"alb_ssl_policy_scan" : alb_ssl_policy_scan,
    "active_root_key_scan" : active_root_key_scan,
    "ec2_default_sg_scan" : ec2_default_sg_scan,
    "lb_log_enabled_scan" : lb_log_enabled_scan,
    "lb_ssl_policy_scan" : lb_ssl_policy_scan,
    "default_vpc_scan" : default_vpc_scan,
    "s3_default_encryption" : s3_default_encryption,
    "sg_scan" : sg_scan,
    "acm_cert_scan" : acm_cert_scan,
    "iam_cert_scan" : iam_cert_scan,
    "sso_check" : sso_check,
    "unencrypted_rds_db_snapshot_scan" : unencrypted_rds_db_snapshot_scan,
    "dynamodb_encryption_scan" : dynamodb_encryption_scan,
    "guardDuty_scan" : guardDuty_scan,
    "check_for_cloud_trail_enabled" : check_for_cloud_trail_enabled,
    "Guard_duty_master_acount_check" : Guard_duty_master_acount_check,
    "get_tenant_ids" : get_tenant_ids,
    "unencrypted_elasticache_redis": unencrypted_elasticache_redis,
    "elasticache_default_port" : elasticache_default_port


    
   
    }
 
AWS_SCANS_TYPE = {
     "guardDuty_scan" : "multi_region",
     "ec2_sg_scan" : "multi_region",
     "ec2_sg_scan_detailed" : "multi_region",
     "lb_log_enabled_scan" : "multi_region",
     "lb_ssl_policy_scan" : "multi_region",
     "default_vpc_scan" : "multi_region",
     "ec2_default_sg_scan" : "multi_region",
     "redshift_cluster_encryption_scan" : "multi_region",
     "s3_default_encryption" : "single_region",
     "active_root_key_scan" : "single_region",
     "sg_scan" : "multi_region",
     "acm_cert_scan" : "multi_region",
     "iam_cert_scan" : "single_region",
     "sso_check" : "single_region",
     "unencrypted_rds_db_snapshot_scan" : "multi_region",
     "dynamodb_encryption_scan" : "multi_region",
     "check_for_cloud_trail_enabled" : "multi_region",
     "Guard_duty_master_acount_check" : "multi_region",
     "get_tenant_ids" : "single_region",
     "unencrypted_elasticache_redis" : "multi_region",
     "elasticache_default_port" : "multi_region"

 }
