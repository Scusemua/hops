import argparse 
import boto3
import botocore 
import json
import logging 
import os 
import socket 
import time 
import yaml

from requests import get

os.system("color")

"""
This script creates all of the infrastrucutre necessary to run λFS and Vanilla HopsFS, 
and to replicate the experiments conducted in the paper, "".

This script should be executed from 
"""

# Set up logging.
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(formatter)
logger.addHandler(ch)

# If True, then print messages will not contain color. Note that colored prints are only supported when running on Linux. 
# This is updated by the command-line arguments. It does not need to be changed manually.
NO_COLOR = False 

# Used to add colors to log messages.
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def log_error(msg):
    if not NO_COLOR:
        msg = bcolors.FAIL + msg + bcolors.ENDC
    logger.error(msg)

def log_warning(msg):
    if not NO_COLOR:
        msg = bcolors.WARNING + msg + bcolors.ENDC
    logger.warning(msg)

def log_success(msg):
    if not NO_COLOR:
        msg = bcolors.OKGREEN + msg + bcolors.ENDC
    logger.info(msg)

def log_important(msg):
    if not NO_COLOR:
        msg = bcolors.OKCYAN + msg + bcolors.ENDC
    logger.info(msg)

print_success = log_success
print_warning = log_warning
print_error = log_error
print_important = log_important

# TODO:
# - Create L-FS infrastrucutre.
#   - Client VM (or will this script be executed from that VM).
#   - Client auto-scaling group.
#   - ZooKeeper nodes. 
# - Create HopsFS infrastrucutre.
#   - Client VM.
#   - Client auto-scaling group.
#   - NameNode auto-scaling group.
# - Create shared infrastrucutre.
#   - EKS cluster.
#   - NDB cluster.
#   - Deploy OpenWhisk.

def get_args() -> argparse.Namespace:
    """
    Parse the commandline arguments.
    """
    parser = argparse.ArgumentParser()
    
    # WHich resources to create.
    parser.add_argument("--create-lfs-client-vm", dest = "create_lambda_fs_client_vm", action = "store_true", help = "If passed, then ONLY create the Client VM for λFS. Once created, this script should be executed from that VM to create the rest of the required AWS infrastructure.")
    parser.add_argument("--skip-hopsfs-infrastrucutre", dest = "skip_hopsfs_infrastrucutre", action = 'store_true', help = "Do not setup infrastrucutre specific to Vanilla HopsFS.")
    parser.add_argument("--skip-lambda-fs-infrastrucutre", dest = "skip_lambda_fs_infrastrucutre", action = 'store_true', help = "Do not setup infrastrucutre specific to λFS.")
    parser.add_argument("--skip-ndb", dest = "skip_ndb", action = "store_true", help = "Do not create MySQL NDB Cluster.")
    parser.add_argument("--skip-vpc", dest = "skip_vpc_creation", action = 'store_true', help = "If passed, then skip the VPC creation step. Note that skipping this step may require additional configuration. See the comments in the provided `wukong_setup_config.yaml` for further information.")
    parser.add_argument("--skip-lambda", dest = "skip_aws_lambda_creation", action = 'store_true', help = "If passed, then skip the creation of the AWS Lambda function(s).")
    
    # Config.
    parser.add_argument("--no-color", dest = "no_color", action = 'store_true', help = "If passed, then no color will be used when printing messages to the terminal.")    
    
    # General AWS-related configuration.
    parser.add_argument("-p", "--aws-profile", dest = 'aws_profile', default = None, type = str, help = "The AWS credentials profile to use when creating the resources. If nothing is specified, then this script will ultimately use the default AWS credentials profile.")
    parser.add_argument("--aws-region", dest = "aws_region", type = str, default = "us-east2", help = "The AWS region in which the AWS resources should be created/provisioned. Default: \"us-east-2\"")
    parser.add_argument("--ip", dest = "user_public_ip", default = "DEFAULT_VALUE", type = str, help = "Your public IP address. We'll create network security rules that will enable this IP address to connect to the EC2 VMs via SSH. If you do not specify this value, then we will attempt to resolve your IP address ourselves.")
    
    # VPC.
    parser.add_argument("--vpc-name", dest = "vpc_name", type = str, default = "LambdaFS_VPC", help = "The name to use for your AWS Virtual Private Cloud (VPC). Default: \"LambdaFS_VPC\"")
    parser.add_argument("--security-group-name", dest = "security_group_name", type = str, default = "lambda-fs-security-group", help = "The name to use for the Security Group. Default: \"lambda-fs-security-group\"")
    # parser.add_argument("--vpc-cidr-block", dest = "vpc_cidr_block", type = str, default = "10.0.0.0/16", help = "IPv4 CIDR block to use when creating the VPC. This should be left as the default value of \"10.0.0.0/16\" unless you know what you're doing. Default value: \"10.0.0.0/16\"")
    return parser.parse_args()

def create_vpc(aws_profile_name:str = None, aws_region:str = "us-east2", vpc_name:str = "LambdaFS_VPC", vpc_cidr_block:str = "10.0.0.0/16", security_group_name:str = "lambda-fs-security-group", user_ip:str = None):
    """
    Create the Virtual Private Cloud that will house all of the infrastructure required by λFS and HopsFS.
    
    Keyword Arguments:
    ------------------
        aws_profile_name (str):
            The AWS credentials profile to use when creating the resources. 
            If None, then this script will ultimately use the default AWS credentials profile.

        NO_COLOR (bool):
            If True, then print messages will not contain color. Note that colored prints are
            only supported when running on Linux.
    """
    if user_ip is None:
        log_error("User IP address cannot be 'None' when creating the AWS VPC.")
        exit(1)
        
    try:
        socket.inet_aton(user_ip)
    except OSError:
        log_error("Invalid user IP address specified when creating AWS VPC: \"%s\"" % user_ip)
        exit(1) 
    
    session:boto3.Session = None 
    if aws_profile_name is not None:
        logger.info("Attempting to create AWS Session using explicitly-specified credentials profile \"%s\" now..." % aws_profile_name)
        try:
            session = boto3.Session(profile_name = aws_profile_name)
            log_success("Successfully created boto3 Session using AWS profile \"%s\"" % aws_profile_name)
        except Exception as ex: 
            log_error("Exception encountered while trying to use AWS credentials profile \"%s\"." % aws_profile_name, no_header = False)
            raise ex 
        ec2_resource = session.resource('ec2', region_name = aws_region)
        ec2_client = session.client('ec2', region_name = aws_region)
    else:
        ec2_resource = boto3.resource('ec2', region_name = aws_region)
        ec2_client = boto3.client('ec2', region_name = aws_region)
    
    log_important("Creating VPC \"%s\" now." % vpc_name)
    
    # Create the VPC.
    create_vpc_response = ec2_client.create_vpc(
        CidrBlock = vpc_cidr_block, 
        TagSpecifications = [{
            'ResourceType': 'vpc',
            'Tags': [{
                'Key': 'Name',
                'Value': vpc_name
            }]
        }])
    vpc = ec2_resource.Vpc(create_vpc_response["Vpc"]["VpcId"])
    vpc.wait_until_available()
    
    log_success("Successfully created a VPC. VPC ID: " + vpc.id)
    logger.info("Next, creating two public subnets.")
    
    # Create the first public subnet.
    public_subnet1 = vpc.create_subnet(
        CidrBlock = "10.0.0.0/20",
        TagSpecifications = [{
            'ResourceType': 'subnet',
            'Tags': [{
                'Key': 'Name',
                'Value': "serverless-mds-subnet-public1"
            }]}])
    ec2_client.modify_subnet_attribute(SubnetId = public_subnet1.id, MapPublicIpOnLaunch = {'Value': True})
    log_success("Successfully created the first public subnet. Subnet ID: " + public_subnet1.id)

    # Create the second public subnet.
    public_subnet2 = vpc.create_subnet(
        CidrBlock = "10.0.16.0/20",
        TagSpecifications = [{
            'ResourceType': 'subnet',
            'Tags': [{
                'Key': 'Name',
                'Value': "serverless-mds-subnet-public2"
            }]}])
    ec2_client.modify_subnet_attribute(SubnetId = public_subnet2.id, MapPublicIpOnLaunch = {'Value': True})
    log_success("Successfully created the second public subnet. Subnet ID: " + public_subnet2.id)
    public_subnets = [public_subnet1, public_subnet2]
    
    logger.info("Next, creating two private subnets.")
    
    # Create the first private subnet.
    private_subnet1 = vpc.create_subnet(
        CidrBlock = "10.0.128.0/20",
        TagSpecifications = [{
        'ResourceType': 'subnet',
        'Tags': [{
            'Key': 'Name',
            'Value': "serverless-mds-subnet-private1"
        }]
    }])
    log_success("Successfully created the first private subnet. Subnet ID: " + private_subnet1.id)
    
    # Create the second private subnet.
    private_subnet2 = vpc.create_subnet(
        CidrBlock = "10.0.144.0/20",
        TagSpecifications = [{
        'ResourceType': 'subnet',
        'Tags': [{
            'Key': 'Name',
            'Value': "serverless-mds-subnet-private2"
        }]
    }])    
    log_success("Successfully created the second private subnet. Subnet ID: " + private_subnet2.id)
    private_subnets = [private_subnet1, private_subnet2]

    logger.info("Next, creating an internet gateway.")
    # Create and attach an internet gateway.
    create_internet_gateway_response = ec2_client.create_internet_gateway(
        TagSpecifications = [{
            'ResourceType': 'internet-gateway',
            'Tags': [{
                'Key': 'Name',
                'Value': "Lambda-FS-InternetGateway"
            }]
        }])
    internet_gateway_id = create_internet_gateway_response["InternetGateway"]["InternetGatewayId"]
    vpc.attach_internet_gateway(InternetGatewayId = internet_gateway_id)
    
    log_success("Successfully created an Internet Gateway and attached it to the VPC. Internet Gateway ID: " + internet_gateway_id)
    logger.info("Next, allocating elastic IP address and creating NAT gateway.")
    
    elastic_ip_response = ec2_client.allocate_address(
        Domain = 'vpc',
        TagSpecifications = [{
            'ResourceType': 'elastic-ip',
            'Tags': [{
                'Key': 'Name',
                'Value': "lambda-fs-nat-gateway-ip"
            }]
        }])
    nat_gateway = ec2_client.create_nat_gateway(
        SubnetId = public_subnet1.id, 
        AllocationId = elastic_ip_response['AllocationId'], 
        TagSpecifications = [{
            'ResourceType': 'natgateway',
            'Tags': [{
                'Key': 'Name',
                'Value': "LambdaFS-NatGateway"
            }]
        }])
    nat_gateway_id = nat_gateway["NatGateway"]["NatGatewayId"]

    log_success("Successfully allocated elastic IP address and created NAT gateway. NAT Gateway ID: " + nat_gateway_id)
    logger.info("Next, creating route tables and associated public route table with public subnet.")
    logger.info("But first, sleeping for ~45 seconds so that the NAT gateway can be created.")

    time.sleep(45)
    
    # The VPC creates a route table, so we have one to begin with. We use this as the public route table.
    initial_route_table = list(vpc.route_tables.all())[0] 
    initial_route_table.create_route(
        DestinationCidrBlock = '0.0.0.0/0',
        GatewayId = internet_gateway_id
    )
    initial_route_table.associate_with_subnet(SubnetId = public_subnet1.id)
    initial_route_table.associate_with_subnet(SubnetId = public_subnet2.id)

    # Now create the private route table.
    private_route_table = vpc.create_route_table(
        TagSpecifications = [{
            'ResourceType': 'route-table',
            'Tags': [{
                'Key': 'Name',
                'Value': "LambdaFS-PrivateRouteTable"
            }]
        }])
    private_route_table.create_route(
        DestinationCidrBlock = '0.0.0.0/0',
        GatewayId = nat_gateway_id
    )

    log_success("Successfully created the route tables and associated public route table with public subnet.")
    logger.info("Next, associating private route table with the private subnets.")
    
    # Associate the private route table with each private subnet.
    private_route_table.associate_with_subnet(SubnetId = private_subnet1.id)
    private_route_table.associate_with_subnet(SubnetId = private_subnet2.id)
    
    log_success("Successfully associated the private route table with the private subnets.")
    logger.info("Next, creating and configuring the security group.")
    
    security_group = ec2_resource.create_security_group(
        Description='Wukong Security Group', GroupName = security_group_name, VpcId = vpc.id,
        TagSpecifications = [{
            "ResourceType": "security-group",
            "Tags": [
                {"Key": "Name", "Value": security_group_name}
            ]
        }])
    
    security_group.authorize_ingress(IpPermissions = [
        {
        # All traffic that originates from within the security group itself.
        "FromPort": 0,
        "ToPort": 65535,
        "IpProtocol": "-1",
        "UserIdGroupPairs": [{
            "GroupId": security_group.id,
            "VpcId": vpc.id}]
        },
        {
        # SSH traffic from your machine's IP address. 
        "FromPort": 22,
        "ToPort": 22,
        "IpProtocol": "tcp",
        "IpRanges": [
            {"CidrIp": user_ip + "/32", "Description": "SSH from my PC"}]
        }
    ])
    
def create_lambda_fs_client_vm():
    """
    Create the λFS client VM. Once created, this script should be executed from the λFS client VM to create the remaining AWS infrastructure.
    """
    pass 

def create_ndb():
    """
    Create the required AWS infrastructure for the MySQL NDB cluster. 
    
    This includes a total of 5 EC2 VMs: one NDB "master" node and four NDB data nodes.
    """
    pass 

def create_eks_openwhisk_cluster(aws_profile_name:str = None, aws_region:str = "us-east2", vpc_name:str = "LambdaFS_VPC"):
    """
    Create the AWS EKS cluster and deploy OpenWhisk on that cluster.
    """
    if aws_profile_name is not None:
        logger.info("Attempting to create AWS Session using explicitly-specified credentials profile \"%s\" now..." % aws_profile_name)
        try:
            session = boto3.Session(profile_name = aws_profile_name)
            log_success("Successfully created boto3 Session using AWS profile \"%s\"" % aws_profile_name)
        except Exception as ex: 
            log_error("Exception encountered while trying to use AWS credentials profile \"%s\"." % aws_profile_name, no_header = False)
            raise ex 
        
        iam = session.client('iam')
    else:
        iam = boto3.client('iam')

def register_openwhisk_namenodes():
    """
    Create and register serverless NameNode functions with the EKS OpenWhisk cluster. 
    """
    pass 

def main():
    global NO_COLOR
    
    command_line_args = get_args() 
    
    logger.info("Welcome to the λFS Interactive Setup.")
    logger.info("Before you continue, please note that many of the components required by λFS (and HopsFS) cost money.")
    logger.info("AWS will begin charging you for these resources as soon as they are created.")
    
    NO_COLOR = command_line_args.no_color
    aws_profile_name = command_line_args.aws_profile
    aws_region = command_line_args.aws_region
    user_public_ip = command_line_args.user_public_ip
    vpc_name = command_line_args.vpc_name
    vpc_cidr_block = command_line_args.vpc_cidr_block
    security_group_name = command_line_args.security_group_name
    
    if user_public_ip == "DEFAULT_VALUE":
        user_public_ip = get('https://api.ipify.org').content.decode('utf8')
    
    try:
        socket.inet_aton(user_public_ip)
    except OSError:
        log_error("Invalid user IP address: \"%s\"" % user_public_ip)
        exit(1) 
    
    # Give the user a chance to verify that the information they specified is correct.
    log_important("Please verify that the following information is correct:")
    logger.info("Selected AWS profile: \"%s\"" % aws_profile_name)
    logger.info("Selected AWS region: \"%s\"" % aws_region)
    logger.info("Your IP address: \"%s\"" % user_public_ip)
    if not command_line_args.skip_vpc_creation:
        if len(vpc_name) == 0:
            log_error("Invalid VPC name specified. VPC name must ")
        logger.info("VPC name: \"%s\"" % vpc_name)
        logger.info("VPC IPv4 CIDR block: \"%s\"" % vpc_cidr_block)
    
    while True:
        proceed = input("\nProceed? [y/n]")
        if proceed.strip().lower() == "y" or proceed.strip().lower() == "yes":
            log_important("Continuing.")
            break 
        elif proceed.strip().lower() == "n" or proceed.strip().lower() == "no":
            log_important("User elected not to continue. This script will now terminate.")
            exit(0)
        else:
            log_error("Please enter \"y\" for yes or \"n\" for no. You entered: \"%s\"" % proceed)
    
    if command_line_args.create_lambda_fs_client_vm:
        logger.info("Creating λFS client virtual machine.")
        success = create_lambda_fs_client_vm()
        
        if not success:
            log_error("Failed to create the λFS client virtual machine.")
            exit(1) 
        else:
            log_success("Successfully created λFS client virtual machine.")
            logger.info("This script will now terminate. Thank you.")
            
        return 

    if not command_line_args.skip_vpc_creation:
        logger.info("Creating Virtual Private Cloud now.")
        create_vpc(
            aws_profile_name = aws_profile_name, 
            aws_region = aws_region, 
            vpc_name = vpc_name, 
            vpc_cidr_block = vpc_cidr_block, 
            security_group_name = security_group_name
        )
        

if __name__ == "__main__":
    main()