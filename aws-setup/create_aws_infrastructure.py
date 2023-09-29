import argparse 
import boto3
import botocore 
import json
import logging 
import os 
import requests 
import socket 
import time 
import urllib3

from time import sleep
from tqdm import tqdm
from requests import get

os.system("color")

"""
This script creates all of the infrastrucutre necessary to run λFS and Vanilla HopsFS, 
and to replicate the experiments conducted in the paper, "".

This script should be executed from 
"""

MYSQL_NDB_MANAGER_AMI = "ami-0a0e055a66e58df2c"
MYSQL_NDB_DATANODE1_AMI = "ami-075e47140b5fd017a"
MYSQL_NDB_DATANODE2_AMI = "ami-0fdbf79b2ec52386e"
HOPSFS_CLIENT_AMI = "ami-01d2cba66e4fe4e1e"
HOPSFS_NAMENODE_AMI = "ami-0cc88cd1a5dfaef18"
LAMBDA_FS_CLIENT_AMI = "ami-027b04d5fece878a8"
LAMBDA_FS_ZOOKEEPER_AMI = "ami-0dbd3f0e8300ba676"

# TODO:
# - Create L-FS infrastrucutre.
#   - Client VM (or will this script be executed from that VM).
#   X - Client auto-scaling group.
#   - ZooKeeper nodes. 
# - Create HopsFS infrastrucutre.
#   - Client VM.
#   X - Client auto-scaling group.
#   - NameNode auto-scaling group.
# - Create shared infrastrucutre.
#   X - Create VPC.
#   X - EKS cluster.
#   - NDB cluster.
#   - Deploy OpenWhisk.
#
# - Script to delete everything. 
    # - Delete NAT gateway.
    # - Delete routes from route tables.
    # - Delete internet gateway.

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
    WARNING = '\033[33m'
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

def create_vpc(
    aws_region:str = "us-east-1",
    vpc_name:str = "LambdaFS_VPC", 
    vpc_cidr_block:str = "10.0.0.0/16", 
    security_group_name:str = "lambda-fs-security-group", 
    user_ip:str = None, 
    ec2_resource = None, 
    ec2_client = None) -> str:
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
            
    Returns:
    --------
        str: vpc id
    
        old:
        dict: A dictionary containing various properties of the newly-created VPC. 
        {
            "vpc_id" (str): The ID of the VPC,
            "subnetIds" (list of str): The IDs of the subnets,
            "securityGroupIds" (list of str): The security group IDs (there should only be one),
        }
    """
    if user_ip is None:
        log_error("User IP address cannot be 'None' when creating the AWS VPC.")
        exit(1)
        
    try:
        socket.inet_aton(user_ip)
    except OSError:
        log_error("Invalid user IP address specified when creating AWS VPC: \"%s\"" % user_ip)
        exit(1) 
    
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
        AvailabilityZone = aws_region + "a",
        TagSpecifications = [{
            'ResourceType': 'subnet',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': "serverless-mds-subnet-public1"
                },
                {
                    'Key': 'PrivacyType',
                    'Value': 'public'
                }
            ]}])
    ec2_client.modify_subnet_attribute(SubnetId = public_subnet1.id, MapPublicIpOnLaunch = {'Value': True})
    log_success("Successfully created the first public subnet. Subnet ID: " + public_subnet1.id)

    # Create the second public subnet.
    public_subnet2 = vpc.create_subnet(
        CidrBlock = "10.0.16.0/20",
        AvailabilityZone = aws_region + "b",
        TagSpecifications = [{
            'ResourceType': 'subnet',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': "serverless-mds-subnet-public2"
                },
                {
                    'Key': 'PrivacyType',
                    'Value': 'public'
                }                
            ]}])
    ec2_client.modify_subnet_attribute(SubnetId = public_subnet2.id, MapPublicIpOnLaunch = {'Value': True})
    log_success("Successfully created the second public subnet. Subnet ID: " + public_subnet2.id)
    # public_subnets = [public_subnet1, public_subnet2]
    
    logger.info("Next, creating two private subnets.")
    
    # Create the first private subnet.
    private_subnet1 = vpc.create_subnet(
        CidrBlock = "10.0.128.0/20",
        AvailabilityZone = aws_region + "a",
        TagSpecifications = [{
        'ResourceType': 'subnet',
        'Tags': [
            {
                'Key': 'Name',
                'Value': "serverless-mds-subnet-private1"
            },
            {
                'Key': 'PrivacyType',
                'Value': 'private'
            }            
        ]
    }])
    log_success("Successfully created the first private subnet. Subnet ID: " + private_subnet1.id)
    
    # Create the second private subnet.
    private_subnet2 = vpc.create_subnet(
        CidrBlock = "10.0.144.0/20",
        AvailabilityZone = aws_region + "b",
        TagSpecifications = [{
        'ResourceType': 'subnet',
        'Tags': [
            {
                'Key': 'Name',
                'Value': "serverless-mds-subnet-private2"
            },
            {
                'Key': 'PrivacyType',
                'Value': 'private'
            }            
        ]
    }])    
    log_success("Successfully created the second private subnet. Subnet ID: " + private_subnet2.id)
    # private_subnets = [private_subnet1, private_subnet2]

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

    for _ in tqdm(range(181)):
        sleep(0.25)
    
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
    logger.info("Next, creating and configuring the security group. Security group name: \"%s\"" % security_group_name)
    
    security_group = ec2_resource.create_security_group(
        Description='LambdaFS security group', GroupName = security_group_name, VpcId = vpc.id,
        TagSpecifications = [{
            "ResourceType": "security-group",
            "Tags": [
                {"Key": "Name", "Value": security_group_name}
            ]
        }])
    
    # TODO: In the actual security group I used, there are two other authorization rules, each of which corresponds to something related to EKS. 
    # If EKS requires its own security group, then we'll need to update these rules once we've created the EKS cluster. 
    security_group.authorize_ingress(IpPermissions = [
        { # All traffic that originates from within the security group itself.
            "FromPort": 0,
            "ToPort": 65535,
            "IpProtocol": "-1",
            "UserIdGroupPairs": [{
                "GroupId": security_group.id,
                "VpcId": vpc.id
            }]
        },
        { # SSH traffic from your machine's IP address. 
            "FromPort": 22,
            "ToPort": 22,
            "IpProtocol": "tcp",
            "IpRanges": [{
                "CidrIp": user_ip + "/32", 
                "Description": "SSH from my PC"
            }]
        }
    ])
    
    log_success("Successfully created and configured security group \"%s\"." % security_group_name)
    print()
    print()
    log_success("=======================")
    log_success("λFS VPC setup complete.")
    log_success("=======================")
    
    return vpc.id
    # return {
    #     "vpc_id": vpc.id,
    #     "securityGroupIds": [],
    #     "subnetIds": []        
    # }
    
def create_lambda_fs_client_vm(
    ec2_client = None,
    ssh_keypair_name:str = None,
):
    """
    Create the λFS client VM. Once created, this script should be executed from the λFS client VM to create the remaining AWS infrastructure.
    """
    if ec2_client is None:
        log_error("EC2 client cannot be null when creating the λFS client VM.")
        exit(1)
    
    if ssh_keypair_name is None:
        log_error("SSH keypair name cannot be null when creating the λFS client VM.")
        exit(1)

def create_ndb(
    ec2_client = None,
    ssh_keypair_name:str = None,
    num_datanodes:int = 4,
    subnet_id:str = None,
    security_group_ids = [],
):
    """
    Create the required AWS infrastructure for the MySQL NDB cluster. 
    
    This includes a total of 5 EC2 VMs: one NDB "master" node and four NDB data nodes.
    """
    if ec2_client is None:
        log_error("EC2 client cannot be null when creating the NDB cluster.")
        exit(1)
    
    if ssh_keypair_name is None:
        log_error("SSH keypair name cannot be null when creating the NDB cluster.")
        exit(1)
        
    # Create the NDB manager server.
    ndb_manager_instance = ec2_client.create_instances(
        MinCount = 1,
        MaxCount = 1,
        ImageId = MYSQL_NDB_MANAGER_AMI,
        InstanceType = "",
        KeyName = ssh_keypair_name,
        SecurityGroupIds = security_group_ids,
        SubnetId=subnet_id,
    )
    
    # Create `num_datanodes` NDB data nodes.

def create_eks_iam_role(iam, iam_role_name:str = "lambda-fs-eks-cluster-role") -> str:
    """
    Create the IAM Role to be used by the AWS EKS Cluster.
    
    Returns:
    --------
        str: The ARN of the newly-created IAM role.
    """
    trust_relationships = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {
                "Service": ["eks.amazonaws.com"]
            },
            "Action": ["sts:AssumeRole"]
        }],
    }
    
    try:
        role_response = iam.create_role(
            RoleName = iam_role_name, 
            Path = "/",
            Description = "Allows access to other AWS service resources that are required to operate clusters managed by EKS. Used by the Lambda-FS EKS cluster.", 
            AssumeRolePolicyDocument = json.dumps(trust_relationships)) 
    except iam.exceptions.EntityAlreadyExistsException:
        print_warning("Exception encountered when creating IAM role for the AWS Lambda functions: `iam.exceptions.EntityAlreadyExistsException`", no_header = False)
        print_warning("Attempting to fetch ARN of existing role with name \"%s\" now..." % iam_role_name, no_header = True)
        
        try:
            role_response = iam.get_role(RoleName = iam_role_name)
        except iam.exceptions.NoSuchEntityException as ex:
            # This really shouldn't happen, as we tried to create the role and were told that the role exists.
            # So, we'll just terminate the script here. The user needs to figure out what's going on at this point. 
            print_error("Exception encountered while attempting to fetch existing IAM role with name \"%s\": `iam.exceptions.NoSuchEntityException`" % iam_role_name, no_header = False)
            print_error("Please verify that the AWS role exists and re-execute the script. Terminating now.", no_header = True)
            exit(1) 
        
    role_arn = role_response['Role']['Arn']
    print_success("Successfully created IAM role. ARN of newly-created role: \"%s\". Next, attaching required IAM role polices." % role_arn)
    
    iam.attach_role_policy(
        PolicyArn = 'arn:aws:iam::aws:policy/AmazonEKSClusterPolicy',
        RoleName = iam_role_name)
    
    return role_arn

def create_eks_openwhisk_cluster(
    aws_profile_name:str = None, 
    aws_region:str = "us-east-1", 
    vpc_name:str = "LambdaFS_VPC", 
    eks_iam_role_name = "lambda-fs-eks-cluster-role", 
    vpc_id:str = None, 
    eks_cluster_name:str = "lambda-fs-eks-cluster",
    create_eks_iam_role = True,
    ec2_client = None
):
    """
    Create the AWS EKS cluster and deploy OpenWhisk on that cluster.
    """
    if vpc_id is None:
        log_error("VPC ID cannot be null when creating the AWS EKS cluster.")
        exit(1)
        
    if aws_profile_name is not None:
        logger.info("Attempting to create AWS Session using explicitly-specified credentials profile \"%s\" now..." % aws_profile_name)
        try:
            session = boto3.Session(profile_name = aws_profile_name)
            log_success("Successfully created boto3 Session using AWS profile \"%s\"" % aws_profile_name)
        except Exception as ex: 
            log_error("Exception encountered while trying to use AWS credentials profile \"%s\"." % aws_profile_name, no_header = False)
            raise ex 
        
        iam = session.client('iam')
        eks = session.client('eks')
    else:
        iam = boto3.client('iam')
        eks = boto3.client('eks')
    
    logger.info("Creating EKS cluster.")
    
    logger.info("Creating IAM role.")
    
    if create_eks_iam_role:
        role_arn = create_eks_iam_role(iam, iam_role_name = eks_iam_role_name)
    else:
        try:
            response = iam.get_role(RoleName = eks_iam_role_name)
        except iam.exceptions.NoSuchEntityException:
            print()
            log_error("Could not find existing IAM role with name \"%s\"." % eks_iam_role_name)
            log_error("Please verify that the IAM role you specified exists and doesn't contain any typos in the name.")
            exit(1)
        
        role_arn = response['Role']['Arn']
    
    # Get the security group ID(s).
    resp = ec2_client.describe_security_groups(
        Filters = [{
            'Name': 'vpc-id',
            'Values': [vpc_id]   
        }]
    )
    security_groups_ids = []
    for security_group in resp['SecurityGroups']:
        security_group_id = security_group['GroupId']
        security_groups_ids.append(security_group_id)
    
    # Get the subnet ID(s).
    resp = ec2_client.describe_subnets(
        Filters = [{
            'Name': 'vpc-id',
            'Values': [vpc_id]   
        }]
    )
    subnet_ids = []
    for subnet in resp['Subnets']:
        subnet_id = subnet['SubnetId']
        subnet_ids.append(subnet_id)
    
    # Create AWS EKS cluster.
    response = eks.create_cluster(  # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/eks/client/create_cluster.html
        name = eks_cluster_name,    # The unique name to give to your cluster.
        version = "1.24",           # Desired kubernetes version.
        roleArn = role_arn,         # The Amazon Resource Name (ARN) of the IAM role that provides permissions for the Kubernetes control plane to make calls to Amazon Web Services API operations on your behalf.
        resourcesVpcConfig = {      # The VPC configuration that’s used by the cluster control plane.
            "subnetIds": subnet_ids,
            "securityGroupIds": security_groups_ids,
            "endpointPublicAccess": True,
            "endpointPrivateAccess": False,
            "publicAccessCidrs": ["0.0.0.0/0"]
        },
        kubernetesNetworkConfig = { # The Kubernetes network configuration for the cluster.
            # "serviceIpv4Cidr": "", # If you don’t specify a block, Kubernetes assigns addresses from either the 10.100.0.0/16 or 172.20.0.0/16 CIDR blocks. Let's just let it do that.
            #"ipFamily": "ipv4"       # Specify which IP family is used to assign Kubernetes pod and service IP addresses. 
        }
    )
    
    cluster_response = response['cluster']
    
    if cluster_response['status'] == 'FAILED':
        log_error("Creation of AWS EKS Cluster has apparently failed.")
        log_error("Full response:")
        log_error(cluster_response)
        exit(1)
    
    log_important("AWS EKS Cluster creation API call succeeded.")
    log_important("According to the AWS documentation, it can typically take 10 - 15 minutes for the cluster to be fully created and become operational.")
    log_important("We will begin creating some of the other components while we wait for the EKS Cluster to finish being created.")

def create_ec2_auto_scaling_group(
    auto_scaling_group_name:str = "",
    launch_configuration_name:str = "",
    launch_template_name:str = "",
    min_size:int = 0,
    max_size:int = 8,
    desired_capacity:int = 0,
    availability_zones:list = [],
    autoscaling_client = None
):
    """
    Create an EC2 auto-scaling group.
    """
    if autoscaling_client is None:
        log_error("Autoscaling client cannot be done when creating an auto-scaling group.")
        exit(1)
        
    logger.info("Creating auto-scaling group \"%s\" with launch template \"%s\"." % (auto_scaling_group_name, launch_template_name))
        
    response = autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName = auto_scaling_group_name,
        LaunchConfigurationName = launch_configuration_name,
        LaunchTemplate = {
            'LaunchTemplateName': launch_template_name,
            'Version': '$Default',
        },
        MinSize = min_size,
        MaxSize = max_size,
        DesiredCapacity = desired_capacity,
        AvailabilityZones = availability_zones,
    )
    
    logger.info("Response from creating auto-scaling group \"%s\": %s" % (auto_scaling_group_name, str(response)))

def create_launch_template(
    launch_template_name:str = "",
    launch_template_description:str = "",
    ec2_client = None,
    vpc_id:str = None,
    ami_id:str = "", 
    instance_type:str = "",
    security_group_ids:list = [],
):
    """
    Create an EC2 Launch Template for use with an EC2 Auto-Scaling Group. 
    """
    if ec2_client is None:
        log_error("EC2 client cannot be null when creating a launch template.")
        exit(1)
    
    response = ec2_client.create_launch_template(
        LaunchTemplateName = launch_template_name,
        VersionDescription = launch_template_description,
        LaunchTemplateData = {
            "ImageID": ami_id,
            "InstanceType": instance_type,
            "SecurityGroupIds": security_group_ids,
            "NetworkInterfaces": [{
                'AssociatePublicIpAddress': True,
                'DeviceIndex': 0,
            }]
        },
        TagSpecifications = [{
            "ResourceType": "vpc",
            "Tags": [{
                "Key": "vpc",
                "Value": vpc_id,
            }]   
        }]
    )
    
    logger.info("Response from creating launch template \"%s\": %s" % (launch_template_name, str(response)))

def create_launch_templates_and_instance_groups(
    ec2_client = None,
    autoscaling_client = None,
    vpc_id:str = None,
    command_line_args:argparse.Namespace = None,
    security_groups_ids:list = []
):
    """
    Create the launch templates and auto-scaling groups for λFS clients, HopsFS clients, and HopsFS NameNodes.
    """

    if not command_line_args.skip_launch_templates:
        logger.info("Creating the EC2 launch templates now.")
        
        # λFS clients.
        create_launch_template(ec2_client = ec2_client, vpc_id = vpc_id, launch_template_name = "lambda_fs_clients", launch_template_description = "LambdaFS_Clients_Ver1", ami_id = LAMBDA_FS_CLIENT_AMI, instance_type = command_line_args.lfs_client_ags_it, security_group_id = security_groups_ids)
        # HopsFS clients.
        create_launch_template(ec2_client = ec2_client, vpc_id = vpc_id, launch_template_name = "hopsfs_clients", launch_template_description = "HopsFS_Clients_Ver1", ami_id = HOPSFS_CLIENT_AMI, instance_type = command_line_args.hopsfs_client_ags_it, security_group_id = security_groups_ids)
        # HopsFS NameNodes.
        create_launch_template(ec2_client = ec2_client, vpc_id = vpc_id, launch_template_name = "hopsfs_namenodes", launch_template_description = "HopsFS_NameNodes_Ver1", ami_id = HOPSFS_NAMENODE_AMI, instance_type = command_line_args.hopsfs_namenode_ags_it, security_group_id = security_groups_ids)
        
        logger.info("Created the EC2 launch templates.")
    else:
        logger.info("Skipping the creation of the EC2 launch templates.")
    
    if not command_line_args.skip_autoscaling_groups:
        logger.info("Creating the EC2 auto-scaling groups now.")
        
        # λFS clients.
        create_ec2_auto_scaling_group(autoscaling_client = autoscaling_client, launch_template_name = "lambda_fs_clients")
        # HopsFS clients.
        create_ec2_auto_scaling_group(autoscaling_client = autoscaling_client, launch_template_name = "hopsfs_clients")
        # HopsFS NameNodes.
        create_ec2_auto_scaling_group(autoscaling_client = autoscaling_client, launch_template_name = "hopsfs_namenodes")
        
        logger.info("Created the EC2 auto-scaling groups.")
    else:
        logger.info("Skipping the creation of the EC2 auto-scaling groups.") 

def register_openwhisk_namenodes():
    """
    Create and register serverless NameNode functions with the EKS OpenWhisk cluster. 
    """
    pass 

def validate_keypair_exists(ssh_keypair_name = None, ec2_client = None)->bool:
    """
    Return true if there exists an SSH keypair with the given name registered with AWS.
    
    WARNING: Terminates/aborts if the ec2_client or ssh_keypair_name parameter is null!
    """
    if ssh_keypair_name is None:
        log_error("No SSH keypair specified (value is null).")
        exit(1)
    
    if ec2_client is None:
        log_error("EC2 client is null.")
        exit(1)
    
    try:
        response = ec2_client.describe_key_pairs(KeyNames=[ssh_keypair_name])
    except botocore.exceptions.ClientError as error:
        log_error(error)
        return False 
    
    if len(response['KeyPairs']) > 1:
        log_error("Somehow found multiple KeyPairs for key-pair name \"%s\"" % ssh_keypair_name) 
        for keypair in response['KeyPairs']:
            log_error("Found: \"%s\"" % keypair['KeyName'])
    
    if response['KeyPairs'][0]['KeyName'] == ssh_keypair_name:
        return True 
    
    return False 

def get_args() -> argparse.Namespace:
    """
    Parse the commandline arguments.
    """
    parser = argparse.ArgumentParser()
    
    # Which resources to create.
    parser.add_argument("--create-lfs-client-vm", dest = "create_lambda_fs_client_vm", action = "store_true", help = "If passed, then ONLY create the Client VM for λFS. Once created, this script should be executed from that VM to create the rest of the required AWS infrastructure.")
    parser.add_argument("--skip-hopsfs-infrastrucutre", dest = "skip_hopsfs_infrastrucutre", action = 'store_true', help = "Do not setup infrastrucutre specific to Vanilla HopsFS.")
    parser.add_argument("--skip-lambda-fs-infrastrucutre", dest = "skip_lambda_fs_infrastrucutre", action = 'store_true', help = "Do not setup infrastrucutre specific to λFS.")
    parser.add_argument("--skip-ndb", dest = "skip_ndb", action = "store_true", help = "Do not create MySQL NDB Cluster.")
    parser.add_argument("--skip-eks", dest = "skip_eks", action = "store_true", help = "Do not create AWS EKS Cluster. If you skip the creation of the AWS EKS cluster, you should pass the name of the existing AWS EKS cluster via the '--eks-cluster-name' command-line argument.")
    parser.add_argument("--skip-vpc", dest = "skip_vpc_creation", action = 'store_true', help = "If passed, then skip the VPC creation step. Note that skipping this step may require additional configuration. See the comments in the provided `wukong_setup_config.yaml` for further information.")
    parser.add_argument("--skip-eks-iam-role-creation", dest = "skip_iam_role_creation", action = 'store_true', help = "If passed, then skip the creation of the IAM role required by the AWS EKS cluster. You must pass the name of the IAM role via the '--eks-iam-role' argument if the role is not created with this script.")    
    parser.add_argument("--skip-auto-scaling-groups", dest = "skip_autoscaling_groups", action = "store_true", help = "If passed, then do not create the EC2 auto-scaling groups (for ).")
    parser.add_argument("--skip-launch-templates-groups", dest = "skip_launch_templates", action = "store_true", help = "If passed, then do not create the EC2 launch templates (for ).")
    
    # Config.
    parser.add_argument("--no-color", dest = "no_color", action = 'store_true', help = "If passed, then no color will be used when printing messages to the terminal.")    
    
    # General AWS-related configuration.
    parser.add_argument("-p", "--aws-profile", dest = 'aws_profile', default = None, type = str, help = "The AWS credentials profile to use when creating the resources. If nothing is specified, then this script will ultimately use the default AWS credentials profile.")
    parser.add_argument("--aws-region", dest = "aws_region", type = str, default = "us-east-1", help = "The AWS region in which the AWS resources should be created/provisioned. Default: \"us-east-2\"")
    parser.add_argument("--ip", dest = "user_public_ip", default = "DEFAULT_VALUE", type = str, help = "Your public IP address. We'll create network security rules that will enable this IP address to connect to the EC2 VMs via SSH. If you do not specify this value, then we will attempt to resolve your IP address ourselves.")
    
    # VPC.
    parser.add_argument("--vpc-name", dest = "vpc_name", type = str, default = "LambdaFS_VPC", help = "The name to use for your AWS Virtual Private Cloud (VPC). If you're skipping the VPC-creation step, then you need to specify the name of an existing VPC to use. Default: \"LambdaFS_VPC\"")
    parser.add_argument("--security-group-name", dest = "security_group_name", type = str, default = "lambda-fs-security-group", help = "The name to use for the Security Group. Default: \"lambda-fs-security-group\"")
    # parser.add_argument("--vpc-cidr-block", dest = "vpc_cidr_block", type = str, default = "10.0.0.0/16", help = "IPv4 CIDR block to use when creating the VPC. This should be left as the default value of \"10.0.0.0/16\" unless you know what you're doing. Default value: \"10.0.0.0/16\"")
    
    # EC2 
    parser.add_argument("-lfs-c-ags-it", "--lfs-client-auto-scaling-group-instance-type", dest = "lfs_client_ags_it", type = str, default = "r5.4xlarge", help = "The EC2 instance type to use for the λFS client auto-scaling group. Default: \"r5.4xlarge\"")
    parser.add_argument("-hfs-c-ags-it","--hopsfs-client-auto-scaling-group-instance-type", dest = "hopsfs_client_ags_it", type = str, default = "r5.4xlarge", help = "The EC2 instance type to use for the HopsFS client auto-scaling group. Default: \"r5.4xlarge\"")
    parser.add_argument("-hfs-nn-ags-it","--hopsfs-namenode-auto-scaling-group-instance-type", dest = "hopsfs_namenode_ags_it", type = str, default = "r5.4xlarge", help = "The EC2 instance type to use for the HopsFS NameNode auto-scaling group. Default: \"r5.4xlarge\"")
    parser.add_argument("--ssh-keypair-name", dest = "ssh_keypair_name", type = str, default = None, help = "The name of the SSH keypair registered with AWS. This MUST be specified when creating any EC2 VMs, as we must pass the name of the keypair to the EC2 API so that you will have SSH access to the virtual machines. There is no default value.")
    parser.add_argument("--num-ndb-datanodes", dest = "num_ndb_datanodes", type = int, default = 4, help = "The number of MySQL NDB Data Nodes to create. Default: 4")
    
    # EKS.
    parser.add_argument("--eks-cluster-name", dest = "eks_cluster_name", type = str, default = "lambda-fs-eks-cluster", help = "The name to use for the AWS EKS cluster. We deploy the FaaS platform OpenWhisk on this EKS cluster. Default: \"lambda-fs-eks-cluster\"")
    parser.add_argument("--eks-iam-role-name", dest = "eks_iam_role_name", type = str, default = "lambda-fs-eks-cluster-role", help = "The name to either use when creating the new IAM role for the AWS EKS cluster, or this is the name of an existing role to use for the cluster (when you also pass the '--skip-eks-iam-role-creation' argument).")
    return parser.parse_args()

def main():
    global NO_COLOR
    
    command_line_args = get_args() 
    
    log_success("Welcome to the λFS Interactive Setup.")
    log_warning("Before you continue, please note that many of the components required by λFS (and HopsFS) cost money.")
    log_warning("AWS will begin charging you for these resources as soon as they are created.")
    print()
    print()
    
    # time.sleep(0.125)
    
    NO_COLOR = command_line_args.no_color
    aws_profile_name = command_line_args.aws_profile
    aws_region = command_line_args.aws_region
    user_public_ip = command_line_args.user_public_ip
    vpc_name = command_line_args.vpc_name
    vpc_cidr_block = "10.0.0.0/16" # command_line_args.vpc_cidr_block
    security_group_name = command_line_args.security_group_name
    eks_cluster_name = command_line_args.eks_cluster_name 
    skip_iam_role_creation = command_line_args.skip_iam_role_creation
    eks_iam_role_name = command_line_args.eks_iam_role_name
    ssh_keypair_name = command_line_args.ssh_keypair_name
    num_ndb_datanodes = command_line_args.num_ndb_datanodes
    
    if user_public_ip == "DEFAULT_VALUE":
        log_warning("Attempting to resolve your IP address automatically...")
        try:
            user_public_ip = get('https://api.ipify.org', timeout = 5).content.decode('utf8')
            log_success("Successfully resolved your IP address.")
            print()
            # time.sleep(0.125)
        except (requests.exceptions.ReadTimeout, urllib3.exceptions.ReadTimeoutError):
            log_error("Could not connect to api.ipify.org to resolve your IP address. Please pass your IP address to this script directly to continue.")
            exit(1)
    
    try:
        socket.inet_aton(user_public_ip)
    except OSError:
        log_error("Invalid user IP address: \"%s\"" % user_public_ip)
        exit(1) 
    
    if aws_profile_name == None:
        log_warning("AWS profile is None.")
        log_warning("If you are unsure what profile to use, you can list the available profiles on your device via the 'aws configure list-profiles' command.")
        log_warning("Execute that command ('aws configure list-profiles') in a terminal or command prompt session to view a list of the available AWS CLI profiles.")
        log_warning("For now, we will use the default profile.")
    else:
        logger.info("Selected AWS profile: \"%s\"" % aws_profile_name)

    # time.sleep(0.25)
    
    print()
    print()
    print()
    log_important("Please verify that the following information is correct before continuing.")
    print()
    
    # time.sleep(0.125)
    
    logger.info("Selected AWS region: \"%s\"" % aws_region)
    logger.info("Your IP address: \"%s\"" % user_public_ip)
    print()
    # time.sleep(0.125)
    if not command_line_args.skip_vpc_creation:
        logger.info("Create VPC: TRUE")
        if len(vpc_name) == 0:
            log_error("Invalid VPC name specified. VPC name must ")
        logger.info("New VPC name: \"%s\"" % vpc_name)
        logger.info("VPC IPv4 CIDR block: \"%s\"" % vpc_cidr_block)
    else:
        logger.info("Create VPC: FALSE")
        logger.info("Existing VPC name: \"%s\"" % vpc_name)
    
    print()
    # time.sleep(0.125)
    if not command_line_args.skip_eks:
        logger.info("Create AWS EKS cluster: TRUE")
        logger.info("New AWS EKS cluster name: \"%s\"" % eks_cluster_name)
    else:
        logger.info("Create AWS EKS cluster: FALSE")
        logger.info("Existing AWS EKS cluster name: \"%s\"" % eks_cluster_name)
    
    print()
    if not skip_iam_role_creation:
        logger.info("Create AWS EKS cluster IAM role: TRUE")
        logger.info("New IAM role name: \"%s\"" % eks_iam_role_name)
    else:
        logger.info("Create AWS EKS cluster IAM role: FALSE")
        logger.info("Existing IAM role name: \"%s\"" % eks_iam_role_name)
    
    print()
    logger.info("λFS client auto-scaling group instance type: %s", command_line_args.lfs_client_ags_it)
    logger.info("HopsFS client auto-scaling group instance type: %s", command_line_args.hopsfs_client_ags_it)
    logger.info("HopsFS NameNode auto-scaling group instance type: %s", command_line_args.hopsfs_namenode_ags_it)
    
    print()
    logger.info("SSH Keypair Name: %s" % ssh_keypair_name)
    
    # time.sleep(0.125)
    
    # Give the user a chance to verify that the information they specified is correct.
    while True:
        print()
        logger.info("Proceed? [y/n]")
        proceed = input(">")
        if proceed.strip().lower() == "y" or proceed.strip().lower() == "yes":
            print() 
            log_important("Continuing.")
            print()
            break 
        elif proceed.strip().lower() == "n" or proceed.strip().lower() == "no":
            log_important("User elected not to continue. This script will now terminate.")
            exit(0)
        else:
            log_error("Please enter \"y\" for yes or \"n\" for no. You entered: \"%s\"" % proceed)
   
    if not validate_keypair_exists(ssh_keypair_name = ssh_keypair_name, ec2_client = ec2_client):
        log_error("Could not find SSH keypair named \"%s\" registered with AWS." % ssh_keypair_name)
        log_error("Please verify that the given keypair exists, is registered with AWS, and has no typos in its name.")
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
        ec2_client = session.client('ec2', region_name = aws_region)
        ec2_resource = session.resource('ec2', region_name = aws_region)
        autoscaling_client = session.client("autoscaling", region_name = aws_region)
    else:
        ec2_client = boto3.client('ec2', region_name = aws_region)
        ec2_resource = boto3.resource('ec2', region_name = aws_region)
        autoscaling_client = boto3.client("autoscaling", region_name = aws_region)

    vpc_id:str = None 
    if not command_line_args.skip_vpc_creation:
        logger.info("Creating Virtual Private Cloud now.")
        vpc_id = create_vpc(
            aws_region = aws_region,
            vpc_name = vpc_name, 
            vpc_cidr_block = vpc_cidr_block, 
            security_group_name = security_group_name,
            user_ip = user_public_ip,
            ec2_client = ec2_client,
            ec2_resource = ec2_resource
        )
    else:
        logger.info("Querying AWS for VPC ID of VPC \"%s\"" % vpc_name)
        resp = ec2_client.describe_vpcs(
            Filters = [{
                'Name': 'tag:Name',
                'Values': [
                    vpc_name  
                ],
            }],
        )
        
        if len(resp['Vpcs']) == 0:
            log_error("Could not find any VPCs with name \"%s\"" % vpc_name)
            exit(1)
        elif len(resp['Vpcs']) > 1:
            log_warning("Found multiple VPCs with name similar to \"%s\"" % vpc_name)
            log_warning("Please enter the number of the VPC you wish to use: ")
            
            counter = 1
            vpc_names = {}
            for vpc in resp['Vpcs']:
                name_of_vpc = None 
                for tag in resp['Vpcs']['Tags']:
                    if tag['Key'] == "Name":
                        name_of_vpc = tag['Value']
                        vpc_names[counter] = name_of_vpc
                        break 
                        
                if name_of_vpc is None:
                    log_error("Could not determine name of one of the VPCs returned by EC2Client::DescribeVPCs: %s" % str(vpc))
                
                print("%d - \"%s\" - %s" % (counter, resp['Vpcs'][0]['VpcId'], name_of_vpc))
                counter += 1
            
            # Ask the user to pick the VPC from all of the VPCs that were returned by the ec2_client.describe_vpcs() call.
            while True:
                selection_str = input(">").strip() 
                
                # Convert to an int.
                try:
                    selection_int = int(selection_str)
                except ValueError:
                    log_error("Please enter a numerical value. You entered \"%s\"" % selection_str)
                    continue
                
                # Make sure it's at least 1.
                if selection_int <= 0:
                    log_error("Please enter a positive numerical value between 1 and %d (inclusive). You entered \"%s\"" % (len(resp['Vpcs']), selection_str))
                    continue
                
                # Make sure it's not too large.
                if selection_int > len(resp['Vpcs']):
                    log_error("Please enter a numerical value between 1 and %d (inclusive). You entered \"%s\"" % (len(resp['Vpcs']), selection_str)) 
                    continue
                
                # Arrays in Python are zero-indexed.
                # But we numbered the choices between 1 and len(resp['Vpcs']).
                # So, subtract one from whatever the user specified. 
                selection_int = selection_int - 1
                
                selected_vpc = resp['Vpcs'][selection_int]
                selected_vpc_id = selected_vpc['VpcId']
                
                user_wants_to_continue = False 
                while True:
                    print() 
                    logger.info("You selected VPC \"%s\" with ID=%s. Is this correct? [y/n]" % (vpc_names[selection_int + 1], selected_vpc_id))
                    
                    correct = input(">").strip() 
                    
                    if correct.strip().lower() == "y" or correct.strip().lower() == "yes":
                        print() 
                        user_wants_to_continue = True 
                        vpc_id = selected_vpc_id
                        print()
                        break 
                    elif correct.strip().lower() == "n" or correct.strip().lower() == "no":
                        log_important("User elected not to continue. This script will now terminate.")
                        print()
                        user_wants_to_continue = False 
                        break 
                    else:
                        log_error("Please enter \"y\" for yes or \"n\" for no. You entered: \"%s\"" % correct)
                        continue
                
                if user_wants_to_continue:
                    log_important("Selected VPC \"%s\" with ID=%s." % (vpc_names[selection_int + 1], selected_vpc_id))
                    break 
                else:
                    log_important("Please enter the number of the VPC you wish to use: ")
                    continue 
        else:
            vpc_id = resp['Vpcs'][0]['VpcId']
            
    log_success("Resolved VPC ID of VPC \"%s\" as %s" % (vpc_name, vpc_id))
        
    create_eks_openwhisk_cluster(
        aws_profile_name = aws_profile_name, 
        aws_region = aws_region, 
        vpc_id = vpc_id,
        vpc_name = vpc_name,
        eks_cluster_name = eks_cluster_name,
        ec2_client = ec2_client,
        create_eks_iam_role = not skip_iam_role_creation,
        eks_iam_role_name = eks_iam_role_name,
    )
    
    logger.info("Creating EC2 launch templates and instance groups now.")
    
    sec_grp_resp = ec2_client.describe_security_groups(
        Filters = [{
            'Name': 'vpc-id',
            'Values': [vpc_id]   
        }]
    )
    security_group_ids = []
    for security_group in sec_grp_resp['SecurityGroups']:
        security_group_id = security_group['GroupId']
        security_group_ids.append(security_group_id)
    
    create_launch_templates_and_instance_groups(
        ec2_client = ec2_client,
        autoscaling_client = autoscaling_client,
        vpc_id = vpc_id,
        command_line_args = command_line_args,
        security_groups_ids = security_group_ids
    )
    
    # Get the subnet ID(s).
    resp_subnet_ids = ec2_client.describe_subnets(
        Filters = [{
            'Name': 'vpc-id',
            'Values': [vpc_id]   
        }]
    )
    subnet_ids = []
    public_subnet_ids = []
    private_subnet_ids = []
    for subnet in resp_subnet_ids['Subnets']:
        subnet_id = subnet['SubnetId']
        subnet_ids.append(subnet_id)
        
        identified_privacy_type = False 
        subnet_name = None 
        for tag in subnet['Tags']:
            if tag['Key'] == 'PrivacyType':
                privacy_type:str = tag['Value']
                
                if privacy_type.strip().lower() == "private":
                    private_subnet_ids.append(subnet_id)
                    identified_privacy_type = True
                    break 
                elif privacy_type.strip().lower() == "public":
                    public_subnet_ids.append(subnet_id)
                    identified_privacy_type = True 
                    break 
                else:
                    log_error("Unexpected value found for \"PrivacyType\" tag for subnet \"%s\": %s" % (subnet_id, privacy_type))
                    exit(1) 
            elif tag['Key'] == 'Name':
                subnet_name = tag['Value']
        
        # If they didn't have the 'PrivacyType' tag, then try to use their name.
        if not identified_privacy_type:
            if subnet_name is not None:
                if "private" in subnet_name.strip().lower():
                    private_subnet_ids.append(subnet_id)
                    identified_privacy_type = True
                elif "public" in subnet_name.strip().lower():
                    public_subnet_ids.append(subnet_id)
                    identified_privacy_type = True 
                else:
                    log_error("Could not identify privacy type of subnet %s (id=%s)" % (subnet_name, subnet_id))
                    exit(1)
            else:
                log_error("Could not identify name or privacy type of subnet %s" % subnet_id)
                exit(1)
    
    if len(subnet_ids) == 0:
        log_error("Could not find any subnets within VPC %s." % vpc_id)
        exit(1)
    
    if len(public_subnet_ids) == 0:
        log_error("Could not find any public subnet IDs.")
        log_error("Subnet IDs: %s" % str(subnet_ids))
        exit(1)

    if len(private_subnet_ids) == 0:
        log_error("Could not find any public subnet IDs.")
        log_error("Subnet IDs: %s" % str(subnet_ids))
        exit(1)
    
    logger.info("Creating MySQL NDB Cluster now.")
    if not command_line_args.skip_ndb:
        create_ndb(ec2_client = ec2_client, ssh_keypair_name = ssh_keypair_name, num_datanodes = num_ndb_datanodes, security_group_ids = security_group_ids, subnet_id = public_subnet_ids[0])
    
    if command_line_args.create_lambda_fs_client_vm:
        logger.info("Creating λFS client virtual machine.")
        success = create_lambda_fs_client_vm(ec2_client = ec2_client, ssh_keypair_name = ssh_keypair_name)
        
        if not success:
            log_error("Failed to create the λFS client virtual machine.")
            exit(1) 
        else:
            log_success("Successfully created λFS client virtual machine.")
            logger.info("This script will now terminate. Thank you.")
            
        return 


if __name__ == "__main__":
    main()