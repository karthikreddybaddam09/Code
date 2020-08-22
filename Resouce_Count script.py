import boto3
import sys
import json
import requests
import api_key
from botocore.client import ClientError



ENVIRONMENT = 'prod'
APIHEADER = {"Authorization" : "API "+api_key.APIKEY[ENVIRONMENT]}

url = 'https://api.cloudplatform.accenture.com'



def get_creds(account, tenant):
	my_url= url + '/account/tenants/' + tenant + '/accounts/' + account
	response=requests.get(my_url,headers=APIHEADER)
	resp=response.json()
	if 'secretId' in resp:
		mySid=resp['secretId']
		my_url= url + '/secret/tenants/' + tenant + '/secrets/' + mySid
		response=requests.get(my_url,headers=APIHEADER)
		resp=response.json()
		if 'secret' in resp:
			return resp['secret']['accessKey'], resp['secret']['secretKey']
	return False, False
	
	


def execute_task( Account, Tenant, access_key, secrete_key):
			
	session = boto3.Session(aws_access_key_id=access_key, aws_secret_access_key=secrete_key)
	client = session.client('ec2')
	regions = client.describe_regions()['Regions']
	region = []
	for i in regions:
		region.append(i['RegionName'])

	for each_region in region:	
		#print ("working on the region %s" % (each_region))
		Ec2_client = session.client('ec2',each_region)
		response = Ec2_client.describe_instances()['Reservations']
		instance_count = 0
		if response == []:	pass 
		else:
			for i in response[0]['Instances']:
				InstanceId = i['InstanceId']
				instance_count+= 1
		print("%s,%s,%s,ec2,%s" % (Account, Tenant, each_region, instance_count ) )
	
	
		rds_client = session.client('rds',each_region)
		response1 = rds_client.describe_db_instances()['DBInstances']
		RDS_database = 0
		if response1 == []:	pass
		else:
			for i in response1:
				DBInstanceIdentifier = i['DBInstanceIdentifier']
				RDS_database+= 1
                print("%s,%s,%s,rds_database,%s" % (Account, Tenant, each_region, RDS_database ) )
	
	
		redshift_client = session.client('redshift',each_region)
		response2 = redshift_client.describe_clusters()['Clusters']
		redshift_database = 0
		if response2 == []:	pass
		else:
			for i in response2:
				ClusterIdentifier = i['ClusterIdentifier']
				redshift_database+= 1
                print("%s,%s,%s,redshift_database,%s" % (Account, Tenant, each_region, redshift_database ) )
	
	
		dynamodb_client = session.client('dynamodb', each_region)
		response3 = dynamodb_client.list_tables()['TableNames']
		dynamodb = 0
		for i in response3:
			dynamo = i
			dynamodb+= 1
                print("%s,%s,%s,dynamodb,%s" % (Account, Tenant, each_region, dynamodb ) )
	
		lambda_client = session.client('lambda', each_region)
		response4 = lambda_client.list_functions()['Functions']
		lambda_count = 0
		if response4 == []:	pass
		else:
			for i in response4:
				FunctionName = i['FunctionName']
				lambda_count+= 1
                print("%s,%s,%s,lambda_function,%s" % (Account, Tenant, each_region, lambda_count ) )


with open("accounts.json") as fh:
        file = json.loads(fh.read())
        TenantId = {}
        for i in file:
                if i['provider'] == 'aws':
                        TenantId[i['providerAccountId']] = i['tenantId']


	

with open('enableCT.txt') as f:
        for i in f.readlines():
                Account = i.strip()

                if Account in TenantId:
                        Tenant = TenantId[Account]
                        access_key, secrete_key = get_creds(Account,Tenant)
                        if access_key and secrete_key:
                                try: execute_task( Account, Tenant, access_key, secrete_key)
                                except Exception as e: print("%s,%s,NA,NA,%s" % (Account, Tenant, str(e) ) )
                        else:
                                print('ERRROR')


                else:
                        print("%s NOT FOUND" % (Account))
