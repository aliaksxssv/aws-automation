import boto3, logging, configparser

# get configuration settings for the AWS GuardDuty
config = configparser.ConfigParser()
config.read('./config/guardduty.ini')

# configure logging
logging.basicConfig(filename=config['logging']['path'], format='%(asctime)s %(levelname)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.INFO)

# configure aws session variables
default_profile_name = config['aws']['profile']
default_region_name = config['aws']['region']

# configure EKS Protection exceptions [{'AccountId':'AWS-ACCOUNT-ID','RegionName':'AWS-REGION-NAME'}]
eks_exception = ''

# get AWS regions
main_session = boto3.Session(profile_name=default_profile_name, region_name=default_region_name)
ec2 = main_session.client('ec2')
regions = ec2.describe_regions()['Regions']

# enable AWS GuarDuty protection plans in each AWS account and region with EKS Protection exceptions
for region in regions:

    regional_session = boto3.Session(profile_name=default_profile_name, region_name=region['RegionName'])
    guardduty = regional_session.client('guardduty')
    detectors = guardduty.list_detectors()['DetectorIds']
    
    for detector in detectors:
        members = guardduty.list_members(DetectorId=detector)['Members']
        
        # enable EKS Protection in Delegated Admin account and for the new AWS accounts
        guardduty.update_detector(DetectorId=detector, Features=[{'Name': 'EKS_AUDIT_LOGS', 'Status': 'ENABLED'}])
        guardduty.update_detector(DetectorId=detector, Features=[{'Name': 'EKS_RUNTIME_MONITORING', 'Status': 'ENABLED', 'AdditionalConfiguration': [{'Name': 'EKS_ADDON_MANAGEMENT','Status': 'ENABLED'}] }])
        guardduty.update_organization_configuration(DetectorId=detector, AutoEnableOrganizationMembers='NEW', Features=[{'Name': 'EKS_AUDIT_LOGS', 'AutoEnable': 'NEW'}])
        guardduty.update_organization_configuration(DetectorId=detector, AutoEnableOrganizationMembers='NEW', Features=[{'Name': 'EKS_RUNTIME_MONITORING', 'AutoEnable': 'NEW', 'AdditionalConfiguration': [{'Name': 'EKS_ADDON_MANAGEMENT','AutoEnable': 'NEW'}] }])

        # enable S3 Protection in Delegated Admin account and for the new AWS accounts
        guardduty.update_detector(DetectorId=detector, Features=[{'Name': 'S3_DATA_EVENTS', 'Status': 'ENABLED'}])
        guardduty.update_organization_configuration(DetectorId=detector, AutoEnableOrganizationMembers='NEW', Features=[{'Name': 'S3_DATA_EVENTS', 'AutoEnable': 'NEW'}])
            
        # enable Malware protection in Delegated Admin account and for the new AWS accounts
        guardduty.update_detector(DetectorId=detector, Features=[{'Name': 'EBS_MALWARE_PROTECTION', 'Status': 'ENABLED'}])
        guardduty.update_malware_scan_settings(DetectorId=detector, EbsSnapshotPreservation='RETENTION_WITH_FINDING')
        guardduty.update_organization_configuration(DetectorId=detector, AutoEnableOrganizationMembers='NEW', Features=[{'Name': 'EBS_MALWARE_PROTECTION', 'AutoEnable': 'NEW'}])
            
        # enable Lambda Protection in Delegated Admin account and for the new AWS accounts
        guardduty.update_detector(DetectorId=detector, Features=[{'Name': 'LAMBDA_NETWORK_LOGS', 'Status': 'ENABLED'}])
        guardduty.update_organization_configuration(DetectorId=detector, AutoEnableOrganizationMembers='NEW', Features=[{'Name': 'LAMBDA_NETWORK_LOGS', 'AutoEnable': 'NEW'}])
            
        # enable RDS Protection in Delegated Admin account and for the new AWS accounts
        guardduty.update_detector(DetectorId=detector, Features=[{'Name': 'RDS_LOGIN_EVENTS', 'Status': 'ENABLED'}])
        guardduty.update_organization_configuration(DetectorId=detector, AutoEnableOrganizationMembers='NEW', Features=[{'Name': 'RDS_LOGIN_EVENTS', 'AutoEnable': 'NEW'}])
        
        for member in members:
            
            # configure EKS Protection in member accounts
            if eks_exception:
                eks_exception_check = False
                for exception in eks_exception:
                    if region['RegionName'] == exception['RegionName'] and member['AccountId'] == exception['AccountId']:
                        eks_exception_check = True
                if eks_exception_check == True:
                    guardduty.update_member_detectors(DetectorId=detector, AccountIds=[member['AccountId']], Features=[{'Name': 'EKS_AUDIT_LOGS', 'Status': 'DISABLED'}])
                    guardduty.update_member_detectors(DetectorId=detector, AccountIds=[member['AccountId']], Features=[{'Name': 'EKS_RUNTIME_MONITORING', 'Status': 'DISABLED', 'AdditionalConfiguration': [{'Name': 'EKS_ADDON_MANAGEMENT','Status': 'DISABLED'}] }])
                    logging.info("EKS Protection  was disabled for the account {0} in {1} region".format(str(region['RegionName']), str(member['AccountId'])))
                else:
                    guardduty.update_member_detectors(DetectorId=detector, AccountIds=[member['AccountId']], Features=[{'Name': 'EKS_AUDIT_LOGS', 'Status': 'ENABLED'}])
                    guardduty.update_member_detectors(DetectorId=detector, AccountIds=[member['AccountId']], Features=[{'Name': 'EKS_RUNTIME_MONITORING', 'Status': 'ENABLED', 'AdditionalConfiguration': [{'Name': 'EKS_ADDON_MANAGEMENT','Status': 'ENABLED'}] }])
                    logging.info("EKS Protection was enabled for the account {0} in {1} region".format(str(region['RegionName']), str(member['AccountId'])))
            else:
                guardduty.update_member_detectors(DetectorId=detector, AccountIds=[member['AccountId']], Features=[{'Name': 'EKS_AUDIT_LOGS', 'Status': 'ENABLED'}])
                guardduty.update_member_detectors(DetectorId=detector, AccountIds=[member['AccountId']], Features=[{'Name': 'EKS_RUNTIME_MONITORING', 'Status': 'ENABLED', 'AdditionalConfiguration': [{'Name': 'EKS_ADDON_MANAGEMENT','Status': 'ENABLED'}] }])
                logging.info("EKS Protection was enabled for the account {0} in {1} region".format(str(region['RegionName']), str(member['AccountId'])))

            # enable S3 Protection in member accounts
            guardduty.update_member_detectors(DetectorId=detector, AccountIds=[member['AccountId']], Features=[{'Name': 'S3_DATA_EVENTS', 'Status': 'ENABLED'}])
            logging.info("S3 Protection was enabled for the account {0} in {1} region".format(str(region['RegionName']), str(member['AccountId'])))
            
            # enable Malware Protection in member accounts
            guardduty.update_member_detectors(DetectorId=detector, AccountIds=[member['AccountId']], Features=[{'Name': 'EBS_MALWARE_PROTECTION', 'Status': 'ENABLED'}])
            logging.info("Malware Protection was enabled for the account {0} in {1} region".format(str(region['RegionName']), str(member['AccountId'])))

            # enable Lambda Protection in member accounts
            guardduty.update_member_detectors(DetectorId=detector, AccountIds=[member['AccountId']], Features=[{'Name': 'LAMBDA_NETWORK_LOGS', 'Status': 'ENABLED'}])
            logging.info("Lambda Protection was enabled for the account {0} in {1} region".format(str(region['RegionName']), str(member['AccountId'])))

            # enable RDS Protection in member accounts
            guardduty.update_member_detectors(DetectorId=detector, AccountIds=[member['AccountId']], Features=[{'Name': 'RDS_LOGIN_EVENTS', 'Status': 'ENABLED'}])
            logging.info("RDS Protection was enabled for the account {0} in {1} region".format(str(region['RegionName']), str(member['AccountId'])))