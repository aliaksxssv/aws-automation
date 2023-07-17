import boto3

#set default aws profile name and region
default_profile_name = ''
default_region_name = ''

main_session = boto3.Session(profile_name=default_profile_name, region_name=default_region_name)

# get available aws regions
ec2 = boto3.client('ec2')
regions = ec2.describe_regions()['Regions']

# enumerate aws regions
for region in regions:
    regional_session = boto3.Session(profile_name='secaudit-admin', region_name=region['RegionName'])
    guardduty = regional_session.client('guardduty')
    detectors = guardduty.list_detectors()['DetectorIds']
    # get detector id
    for detector in detectors:
        # get guardduty member accounts across all regions
        members = guardduty.list_members(DetectorId=detector)['Members']
        # enable rds protection in delegated admin account across all regions
        guardduty.update_detector(DetectorId=detector, Features=[{'Name': 'RDS_LOGIN_EVENTS', 'Status': 'ENABLED'}])
        # enable rds protection for the new member accounts across all regions
        guardduty.update_organization_configuration(DetectorId=detector, AutoEnableOrganizationMembers='NEW', Features=[{'Name': 'RDS_LOGIN_EVENTS', 'AutoEnable': 'NEW'}])
        # enable rds protection for member accounts across all regions
        for member in members:
            guardduty.update_member_detectors(DetectorId=detector, AccountIds=[member['AccountId']], Features=[{'Name': 'RDS_LOGIN_EVENTS', 'Status': 'ENABLED'}])
