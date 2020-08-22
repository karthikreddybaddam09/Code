import boto3
from botocore.client import ClientError

session = boto3.Session(profile_name = 'lol')
client = session.client('ec2')

regions = [k['RegionName'] for k in client.describe_regions()['Regions']]
print (regions)

for region in regions:
	session = boto3.Session(region_name = region,profile_name = 'lol')
	client = session.client('guardduty')
	print (f'working in region {region}')
	try:
		DetectorIds = client.list_detectors()
		print (DetectorIds)
		#master = client.get_master_account(DetectorId=DetectorIds)['Master']['AccountId']
		#print (master)
		#member = client.disassociate_from_master_account(DetectorId=DetectorIds)
		#response = client.delete_detector(DetectorId=DetectorIds)
		#print ('deleted detector')
	except KeyError as e:
		print (e)
	except IndexError as e:
		print (e)