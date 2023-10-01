import argparse 
import boto3
import botocore 
import json
import logging 
import os 
import paramiko 
import requests 
import socket 
import time 
import urllib3
import yaml 

from datetime import datetime
from paramiko.client import SSHClient, AutoAddPolicy
from paramiko.rsakey import RSAKey
from requests import get
from time import sleep
from tqdm import tqdm

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

# Starts ZooKeeper.
START_ZK_COMMAND = "sudo /opt/zookeeper/bin/zkServer.sh start"

# TODO:
# X - Create λFS infrastrucutre.
#   X - Client VM (or will this script be executed from that VM).
#   X - Client auto-scaling group.
#   X - ZooKeeper nodes. 
#   X - Update configuration of ZooKeeper nodes via SSH.
#   - Execute scripts to populate ZooKeeper.
# X - Create HopsFS infrastrucutre.
#   X - Client VM.
#   X - Client auto-scaling group.
#   X - NameNode auto-scaling group.
# - Create shared infrastrucutre.
#   X - Create VPC.
#   X - EKS cluster.
#   X - NDB cluster.
#   - Update configuration of NDB via SSH.
#   - Execute scripts to populate initial tables in NDB.
#   - Deploy OpenWhisk.
#
# X - Make it so you can use YAML instead to pass everything in. 
# - Add documentation to sample config.
#
# - Script to delete everything. 
#   - Need to persist IDs and stuff to a file so we can retrieve them after the script runs, perhaps.
#   - Delete NAT gateway.
#   - Delete routes from route tables.
#   - Delete internet gateway.

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
    if user_ip == None:
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
    
def create_hops_fs_client_vm(
    ec2_resource = None,
    instance_type:str = "r5.4xlarge",
    ssh_keypair_name:str = None,
    subnet_id:str = None,
    security_group_ids:list = [],
)->str:
    """
    Create the primary HopsFS client VM. Once created, this script should be executed from the λFS client VM to create the remaining AWS infrastructure.
    
    Return:
    -------
        str: the ID of the newly-created HopsFS client VM.
    """
    if ec2_resource == None:
        log_error("EC2 client cannot be null when creating the HopsFS client VM.")
        exit(1)
    
    if ssh_keypair_name == None:
        log_error("SSH keypair name cannot be null when creating the HopsFS client VM.")
        exit(1)
    
    hops_fs_client_vm = ec2_resource.create_instances(
        MinCount = 1,
        MaxCount = 1,
        ImageId = HOPSFS_CLIENT_AMI,
        InstanceType = instance_type,
        KeyName = ssh_keypair_name,
        NetworkInterfaces = [{
            "AssociatePublicIpAddress": True,
            "DeviceIndex": 0,
            "SubnetId": subnet_id,
                "Groups": security_group_ids
        }],
        TagSpecifications=[{
            'ResourceType': 'instance',
            'Tags': 
                [
                    {
                    'Key': 'Name',
                    'Value': "hops-fs-client-driver"
                    },
                    {
                    'Key': 'Project',
                    'Value': 'LambdaFS'
                    }
                ]
        }]  
    )
    
    return hops_fs_client_vm[0].id   

def create_lambda_fs_client_vm(
    ec2_resource = None,
    instance_type:str = "r5.4xlarge",
    ssh_keypair_name:str = None,
    subnet_id:str = None,
    security_group_ids:list = [],
)->str:
    """
    Create the primary λFS client VM. Once created, this script should be executed from the λFS client VM to create the remaining AWS infrastructure.
    
    Return:
    -------
        str: the ID of the newly-created λFS client VM.
    """
    if ec2_resource == None:
        log_error("EC2 client cannot be null when creating the λFS client VM.")
        exit(1)
    
    if ssh_keypair_name == None:
        log_error("SSH keypair name cannot be null when creating the λFS client VM.")
        exit(1)
    
    lambda_fs_client_vm = ec2_resource.create_instances(
        MinCount = 1,
        MaxCount = 1,
        ImageId = LAMBDA_FS_CLIENT_AMI,
        InstanceType = instance_type,
        KeyName = ssh_keypair_name,
        NetworkInterfaces = [{
            "AssociatePublicIpAddress": True,
            "DeviceIndex": 0,
            "SubnetId": subnet_id,
                "Groups": security_group_ids
        }],
        TagSpecifications=[{
            'ResourceType': 'instance',
            'Tags': [{
                    'Key': 'Name',
                    'Value': "lambda-fs-client-driver"
                    },
                    {
                    'Key': 'Project',
                    'Value': 'LambdaFS'
                    }]
        }]  
    )
    
    return lambda_fs_client_vm[0].id  

def create_ndb(
    ec2_resource = None,
    ssh_keypair_name:str = None,
    num_datanodes:int = 4,
    subnet_id:str = None,
    ndb_manager_instance_type:str = "r5.4xlarge",
    ndb_datanode_instance_type:str = "r5.4xlarge",
    security_group_ids:list = [],
): 
    """
    Create the required AWS infrastructure for the MySQL NDB cluster. 
    
    This includes a total of 5 EC2 VMs: one NDB "master" node and four NDB data nodes.
    
    Returns a dictionary {
        "manager-node-id": the ID of the manager node VM
        "data-node-ids": list of IDs of the data node VMs
    }
    """
    if ec2_resource == None:
        log_error("EC2 resource cannot be null when creating the NDB cluster.")
        exit(1)
    
    if ssh_keypair_name == None:
        log_error("SSH keypair name cannot be null when creating the NDB cluster.")
        exit(1)
        
    
    logger.info("Creating 1 MySQL NDB Manager Node.")
    
    # Create the NDB manager server.
    ndb_manager_instance = ec2_resource.create_instances(
        MinCount = 1,
        MaxCount = 1,
        ImageId = MYSQL_NDB_MANAGER_AMI,
        InstanceType = ndb_manager_instance_type,
        KeyName = ssh_keypair_name,
        NetworkInterfaces = [{
            "AssociatePublicIpAddress": True,
            "DeviceIndex": 0,
            "SubnetId": subnet_id,
                "Groups": security_group_ids
        }],
        TagSpecifications=[{
            'ResourceType': 'instance',
            'Tags': [{
                        'Key': 'Name',
                        'Value': "ndb-manager-node"
                    },
                    {
                        'Key': 'Project',
                        'Value': 'LambdaFS'
                    }]
        }]  
    )
    
    num_type_1_datanodes = num_datanodes // 2
    if num_datanodes % 2 == 0:
        num_type_2_datanodes = num_type_1_datanodes
    else:
        num_type_2_datanodes = num_type_1_datanodes+1 
        
    logger.info("Creating %d type 1 NDB data node(s) and %d type 2 NDB data node(s)." % (num_type_1_datanodes, num_type_2_datanodes))
    
    type1_datanodes = []
    type2_datanodes = []
    datanodes = [] 
    
    logger.info("Creating %d Type 1 MySQL NDB Data Node(s)." % num_type_1_datanodes)
    
    ndb_datanode_index = 0
    for _ in range(0, num_type_1_datanodes):
        instance_name = "ndb-datanode-type1-%d" % ndb_datanode_index
        ndb_datanode_index += 1
        # Create `num_datanodes` NDB data nodes.
        type1_datanode = ec2_resource.create_instances(
            MinCount = 1,
            MaxCount = 1,
            ImageId = MYSQL_NDB_MANAGER_AMI,
            InstanceType = ndb_datanode_instance_type,
            KeyName = ssh_keypair_name,
            NetworkInterfaces = [{
                "AssociatePublicIpAddress": True,
                "DeviceIndex": 0,
                "SubnetId": subnet_id,
                "Groups": security_group_ids
            }],
            TagSpecifications=[{
                'ResourceType': 'instance',
                'Tags': [{
                            'Key': 'Name',
                            'Value': instance_name
                        },
                        {
                            'Key': 'Project',
                            'Value': 'LambdaFS'
                        }]
            }]   
        ) # end of call to ec2_client.create_instances()
        type1_datanodes.append(type1_datanode[0].id)
        datanodes.append(type1_datanode[0].id)
    
    logger.info("Creating %d Type 2 MySQL NDB Data Node(s)." % num_type_2_datanodes)
    
    for _ in range(0, num_type_2_datanodes):
        instance_name = "ndb-datanode-type2-%d" % ndb_datanode_index
        ndb_datanode_index += 1
        type2_datanode = ec2_resource.create_instances(
            MinCount = 1,
            MaxCount = 1,
            ImageId = MYSQL_NDB_MANAGER_AMI,
            InstanceType = ndb_datanode_instance_type,
            KeyName = ssh_keypair_name,
            NetworkInterfaces = [{
                "AssociatePublicIpAddress": True,
                "DeviceIndex": 0,
                "SubnetId": subnet_id,
                "Groups": security_group_ids
            }],
            TagSpecifications=[{
                'ResourceType': 'instance',
                'Tags': [{
                            'Key': 'Name',
                            'Value': instance_name
                        },
                        {
                            'Key': 'Project',
                            'Value': 'LambdaFS'
                        }]
            }], 
        ) # end of call to ec2_client.create_instances()
        type2_datanodes.append(type2_datanode[0].id)
        datanodes.append(type2_datanode[0].id)
    
    logger.info("Created NDB EC2 instances.")
    logger.info("Created 1 NDB Manager Node and %d NDB DataNode(s)." % len(datanodes))
    return {
        "manager-node-id": ndb_manager_instance[0].id,
        "data-node-ids": datanodes
    }

def create_lambda_fs_zookeeper_vms(
    ec2_resource = None,
    ssh_keypair_name:str = None,
    num_vms:int = 3,
    subnet_id:str = None,
    instance_type:str = "r5.4xlarge",
    security_group_ids = [],
):
    """
    Create the λFS ZooKeeper nodes.
    
    Return a list of str of the IDs of the newly-created λFS ZooKeeper nodes.
    """
    if ec2_resource == None:
        log_error("EC2 resource cannot be null when creating the λFS ZooKeeper nodes.")
        exit(1)
    
    if ssh_keypair_name == None:
        log_error("SSH keypair name cannot be null when creating the λFS ZooKeeper nodes.")
        exit(1)
        
    
    logger.info("Creating %d λFS ZooKeeper node(s) of type %s." % (num_vms, instance_type))
    
    zookeeper_node_ids = []
    for i in range(0, num_vms):
        instance_name = "lambdafs-zookeeper-%d" % i
        zoo_keeper_node = ec2_resource.create_instances(
            MinCount = 1,
            MaxCount = 1,
            ImageId = LAMBDA_FS_ZOOKEEPER_AMI,
            InstanceType = instance_type,
            KeyName = ssh_keypair_name,
            NetworkInterfaces = [{
                "AssociatePublicIpAddress": True,
                "DeviceIndex": 0,
                "SubnetId": subnet_id,
                    "Groups": security_group_ids
            }],
            TagSpecifications=[{
                'ResourceType': 'instance',
                'Tags': [{
                            'Key': 'Name',
                            'Value': instance_name
                        },
                        {
                            'Key': 'Project',
                            'Value': 'LambdaFS'
                        }]
            }]  
        )
        zookeeper_node_ids.append(zoo_keeper_node[0].id)
    
    return zookeeper_node_ids

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
    if vpc_id == None:
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
    security_group_ids = []
    for security_group in resp['SecurityGroups']:
        security_group_id = security_group['GroupId']
        security_group_ids.append(security_group_id)
    
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
            "securityGroupIds": security_group_ids,
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
    launch_template_name:str = "",
    min_size:int = 0,
    max_size:int = 8,
    desired_capacity:int = 0,
    availability_zones:list = [],
    autoscaling_client = None
):
    """
    Create an EC2 auto-scaling group.
    
    Returns a 2-tuple where the first element is the newly-created launch template's name and the second is the template's ID.
    """
    if autoscaling_client == None:
        log_error("Autoscaling client cannot be done when creating an auto-scaling group.")
        exit(1)
        
    logger.info("Creating auto-scaling group \"%s\" with launch template \"%s\"." % (auto_scaling_group_name, launch_template_name))
        
    response = autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName = auto_scaling_group_name,
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
    
    # asg_name = response
    # asg_id = response
    
    # return asg_name, asg_id

def create_launch_template(
    launch_template_name:str = "",
    launch_template_description:str = "",
    ec2_client = None,
    ami_id:str = "", 
    instance_type:str = "",
    security_group_ids:list = [],
):
    """
    Create an EC2 Launch Template for use with an EC2 Auto-Scaling Group. 
    
    Returns a 2-tuple where the first element is the newly-created launch template's name and the second is the template's ID.
    """
    if ec2_client == None:
        log_error("EC2 client cannot be null when creating a launch template.")
        exit(1)
    
    response = ec2_client.create_launch_template(
        LaunchTemplateName = launch_template_name,
        VersionDescription = launch_template_description,
        LaunchTemplateData = {
            "ImageId": ami_id,
            "InstanceType": instance_type,
            "SecurityGroupIds": security_group_ids,
            "NetworkInterfaces": [{
                'AssociatePublicIpAddress': True,
                'DeviceIndex': 0,
            }]
        }
    )
    
    logger.info("Response from creating launch template \"%s\": %s" % (launch_template_name, str(response)))
    
    template_name = response['LaunchTemplate']['LaunchTemplateName']
    template_id = response['LaunchTemplate']['LaunchTemplateId']
    
    return template_name, template_id 

def create_launch_templates_and_instance_groups(
    ec2_client = None,
    autoscaling_client = None,
    lfs_client_ags_it:str = "r5.4xlarge",
    hopsfs_client_ags_it:str = "r5.4xlarge",
    hopsfs_namenode_ags_it:str = "r5.4xlarge",
    skip_launch_templates:bool = False,
    skip_autoscaling_groups:bool = False,
    security_group_ids:list = [],
    data = {}
):
    """
    Create the launch templates and auto-scaling groups for λFS clients, HopsFS clients, and HopsFS NameNodes.
    """

    if not skip_launch_templates:
        logger.info("Creating the EC2 launch templates now.")
        
        # λFS clients.
        name, id = create_launch_template(ec2_client = ec2_client, launch_template_name = "lambda_fs_clients", launch_template_description = "LambdaFS_Clients_Ver1", ami_id = LAMBDA_FS_CLIENT_AMI, instance_type = lfs_client_ags_it, security_group_ids = security_group_ids)
        
        data["lfs-client-launch-template-name"] = name
        data["lfs-client-launch-template-id"] = id 
        
        # HopsFS clients.
        name, id = create_launch_template(ec2_client = ec2_client, launch_template_name = "hopsfs_clients", launch_template_description = "HopsFS_Clients_Ver1", ami_id = HOPSFS_CLIENT_AMI, instance_type = hopsfs_client_ags_it, security_group_ids = security_group_ids)
        
        data["hospfs-client-launch-template-name"] = name
        data["hospfs-client-launch-template-id"] = id 
        
        # HopsFS NameNodes.
        name, id = create_launch_template(ec2_client = ec2_client, launch_template_name = "hopsfs_namenodes", launch_template_description = "HopsFS_NameNodes_Ver1", ami_id = HOPSFS_NAMENODE_AMI, instance_type = hopsfs_namenode_ags_it, security_group_ids = security_group_ids)
        
        data["hopsfs-nn-launch-template-name"] = name
        data["hopsfs-nn-launch-template-id"] = id 
        
        logger.info("Created the EC2 launch templates.")
    else:
        logger.info("Skipping the creation of the EC2 launch templates.")
    
    if not skip_autoscaling_groups:
        logger.info("Creating the EC2 auto-scaling groups now.")
        
        # λFS clients.
        create_ec2_auto_scaling_group(auto_scaling_group_name = "lambda_fs_clients_ags", autoscaling_client = autoscaling_client, launch_template_name = "lambda_fs_clients")
        # HopsFS clients.
        create_ec2_auto_scaling_group(auto_scaling_group_name = "hopsfs_clients_ags",autoscaling_client = autoscaling_client, launch_template_name = "hopsfs_clients")
        # HopsFS NameNodes.
        create_ec2_auto_scaling_group(auto_scaling_group_name = "hopsfs_namenodes_ags",autoscaling_client = autoscaling_client, launch_template_name = "hopsfs_namenodes")
        
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
    if ssh_keypair_name == None:
        print()
        log_error("No SSH keypair specified (value is null).")
        exit(1)
    
    if ec2_client == None:
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

def update_zookeeper_config(
    ec2_client = None,
    instance_ids:list = [],
    ssh_key_path:str = None,
    zookeeper_jvm_heap_size:int = 4000,
    data:dict = {}
):
    """
    Update the configuration information on the ZooKeeper VMs.
    
    Returns:
    --------
        list of str: The public IP addresses of the newly-created ZooKeeper nodes.
    """
    
    config = """ \
tickTime=1000
dataDir=/data/zookeeper
dataLogDir=/disk2/zookeeper/logs
clientPort=2181
initLimi =5
syncLimit=2
admin.serverPort=8081
autopurge.snapRetainCount=3
autopurge.purgeInterval=24
"""

    ssh_key_path = "C:/Users/benrc/.ssh/bcarver.pem"

    resp = ec2_client.describe_instances(InstanceIds = instance_ids)
    instance_private_dns_names = []
    instance_public_ips = []
    for i,reservation in enumerate(resp['Reservations']):
        private_dns_name = reservation['Instances'][0]['PrivateDnsName']
        public_ip = reservation['Instances'][0]['PublicIpAddress']
        logger.info("Private DNS name of ZooKeeper VM #%d: %s" % (i, private_dns_name))
        logger.info("Public IP address of ZooKeeper VM #%d: %s" % (i, public_ip))
        instance_private_dns_names.append(private_dns_name)
        instance_public_ips.append(public_ip)

    for i,private_dns_name in enumerate(instance_private_dns_names):
        config = config + ("server.%d=%s:2888:3888" % (i, private_dns_name)) + "\n"

    logger.info("Configuration file:\n%s" % str(config))

    key = RSAKey(filename = ssh_key_path)

    for i,ip in enumerate(instance_public_ips):
        ssh_client = SSHClient()
        ssh_client.set_missing_host_key_policy(AutoAddPolicy)
        logger.info("Connecting to ZooKeeper VM #%d at %s" % (i, ip))
        ssh_client.connect(hostname = ip, port = 22, username = "ubuntu", pkey = key)
        logger.info("Connected!")
        
        sftp_client = ssh_client.open_sftp()
        file = sftp_client.open("/home/ubuntu/zk/conf/zoo.cfg", mode = "w")
        
        file.write(config)
        file.close()
        
        zk_env_file = sftp_client.open("/opt/zookeeper/conf/zookeeper-env.sh", mode = "w")
        zk_env_file.write("ZK_SERVER_HEAP=\"%d\"\n" % zookeeper_jvm_heap_size)
        zk_env_file.write("JVMFLAGS=\"-Xms%dm\"\n" % zookeeper_jvm_heap_size)
        zk_env_file.close()
        
        ssh_client.exec_command("echo %d > /data/zookeeper/myid" % i)
        
        ssh_client.close()
    
    data["zk_node_public_IPs"] = instance_public_ips
    data["zk_node_private_dns_names"] = instance_private_dns_names
    
    return instance_public_ips

def start_zookeeper_cluster(
    ips = [],
    ssh_key_path = None,
):
    """
    Start the ZooKeeper cluster.
    """
    if ips == None or len(ips) == 0:
        log_error("Received no ZooKeeper IP addresses. Cannot start the server.")
        return 
    
    if ssh_key_path == None:
        log_error("SSH key path cannot be None.")
        exit(1)
    
    key = RSAKey(filename = ssh_key_path)

    for ip in ips:
        ssh_client = SSHClient()
        ssh_client.set_missing_host_key_policy(AutoAddPolicy)
        logger.info("Connecting to ZooKeeper VM at %s" % ip)
        ssh_client.connect(hostname = ip, port = 22, username = "ubuntu", pkey = key)
        logger.info("Connected!")
        
        ssh_client.exec_command("sudo /opt/zookeeper/bin/zkServer.sh start")
        
        ssh_client.close()
        
def populate_zookeeper(
    ips = [],
    ssh_key_path = None,
):
    """
    SFTP the script used to populate ZooKeeper with data to a ZooKeeper node and then execute it.
    """
    if ips == None or len(ips) == 0:
        log_error("Received no ZooKeeper IP addresses. Cannot start the server.")
        return 
        
    if ssh_key_path == None:
        log_error("SSH key path cannot be None.")
        exit(1)

    target_server_ip = ips[0]
    logger.info("Connecting to ZooKeeper server at %s to populate cluster." % target_server_ip)
    
    key = RSAKey(filename = ssh_key_path)

    ssh_client = SSHClient()
    ssh_client.set_missing_host_key_policy(AutoAddPolicy)
    logger.info("Connecting to ZooKeeper VM at %s" % target_server_ip)
    ssh_client.connect(hostname = target_server_ip, port = 22, username = "ubuntu", pkey = key)
    logger.info("Connected!")
    
    sftp = ssh_client.open_sftp()
    sftp.put("./populate_zk_script", "/home/ubuntu/populate_zk_script")
    
    ssh_client.exec_command("sudo /opt/zookeeper/bin/zkCli.sh < /home/ubuntu/populate_zk_script")
    ssh_client.close()

def get_args() -> argparse.Namespace:
    """
    Parse the commandline arguments.
    """
    parser = argparse.ArgumentParser()
    
    # YAML
    parser.add_argument("-y", "--yaml", type = str, default = None, help = "The path of a YAML configuration file.") #, which can be used in-place of command-line arguments. If nothing is passed for this, then command-line arguments will be used. If a YAML file is passed, then command-line arguments for properties that CAN be defined in YAML will be ignored (even if you did not define them in the YAML file).")
    
    # Which resources to create.
    # parser.add_argument("--create-lfs-client-vm", dest = "create_lambda_fs_client_vm", action = "store_true", help = "If passed, then create the primary Client VM for λFS. Once created, this script should be executed from that VM to create the rest of the required AWS infrastructure.")
    # parser.add_argument("--create-hopsfs-client-vm", dest = "create_hops_fs_client_vm", action = "store_true", help = "If passed, then create the primary Client VM for HopsFS. Once created, this script should be executed from that VM to create the rest of the required AWS infrastructure.")
    # parser.add_argument("--skip-hopsfs-infrastrucutre", dest = "skip_hopsfs_infrastrucutre", action = 'store_true', help = "Do not setup infrastrucutre specific to Vanilla HopsFS.")
    # parser.add_argument("--skip-lambda-fs-infrastrucutre", dest = "skip_lambda_fs_infrastrucutre", action = 'store_true', help = "Do not setup infrastrucutre specific to λFS.")
    # parser.add_argument("--skip-ndb", dest = "skip_ndb", action = "store_true", help = "Do not create the MySQL NDB Cluster.")
    # parser.add_argument("--skip-zookeeper", dest = "skip_zookeeper", action = "store_true", help = "Do not create the λFS ZooKeeper nodes.")
    # parser.add_argument("--skip-eks", dest = "skip_eks", action = "store_true", help = "Do not create AWS EKS Cluster. If you skip the creation of the AWS EKS cluster, you should pass the name of the existing AWS EKS cluster via the '--eks-cluster-name' command-line argument.")
    # parser.add_argument("--skip-vpc", dest = "skip_vpc_creation", action = 'store_true', help = "If passed, then skip the VPC creation step. Note that skipping this step may require additional configuration. See the comments in the provided `wukong_setup_config.yaml` for further information.")
    # parser.add_argument("--skip-eks-iam-role-creation", dest = "skip_iam_role_creation", action = 'store_true', help = "If passed, then skip the creation of the IAM role required by the AWS EKS cluster. You must pass the name of the IAM role via the '--eks-iam-role' argument if the role is not created with this script.")    
    # parser.add_argument("--skip-auto-scaling-groups", dest = "skip_autoscaling_groups", action = "store_true", help = "If passed, then do not create the EC2 auto-scaling groups (for ).")
    # parser.add_argument("--skip-launch-templates-groups", dest = "skip_launch_templates", action = "store_true", help = "If passed, then do not create the EC2 launch templates (for ).")
    
    # # Config.
    # parser.add_argument("--no-color", dest = "no_color", action = 'store_true', help = "If passed, then no color will be used when printing messages to the terminal.")    
    
    # parser.add_argument("--ssh-keypair-name", dest = "ssh_keypair_name", type = str, default = None, help = "The name of the RSA SSH keypair registered with AWS. This MUST be specified when creating any EC2 VMs, as we must pass the name of the keypair to the EC2 API so that you will have SSH access to the virtual machines. There is no default value. Needs to be RSA. If you don't have an RSA key, then please create a new RSA key and add that to your AWS account.")
    # parser.add_argument("--ssh-key-path", dest = "ssh_key_path", type = str, default = None, help = "Path to the RSA SSH key. Needs to be RSA format. If you don't have an RSA key, then please create a new RSA key and add that to your AWS account.")
    
    # # General AWS-related configuration.
    # parser.add_argument("-p", "--aws-profile", dest = 'aws_profile', default = None, type = str, help = "The AWS credentials profile to use when creating the resources. If nothing is specified, then this script will ultimately use the default AWS credentials profile.")
    # parser.add_argument("--aws-region", dest = "aws_region", type = str, default = "us-east-1", help = "The AWS region in which the AWS resources should be created/provisioned. Default: \"us-east-2\"")
    # parser.add_argument("--ip", dest = "user_public_ip", default = "DEFAULT_VALUE", type = str, help = "Your public IP address. We'll create network security rules that will enable this IP address to connect to the EC2 VMs via SSH. If you do not specify this value, then we will attempt to resolve your IP address ourselves.")
    
    # # VPC.
    # parser.add_argument("--vpc-name", dest = "vpc_name", type = str, default = "LambdaFS_VPC", help = "The name to use for your AWS Virtual Private Cloud (VPC). If you're skipping the VPC-creation step, then you need to specify the name of an existing VPC to use. Default: \"LambdaFS_VPC\"")
    # parser.add_argument("--security-group-name", dest = "security_group_name", type = str, default = "lambda-fs-security-group", help = "The name to use for the Security Group. Default: \"lambda-fs-security-group\"")
    # # parser.add_argument("--vpc-cidr-block", dest = "vpc_cidr_block", type = str, default = "10.0.0.0/16", help = "IPv4 CIDR block to use when creating the VPC. This should be left as the default value of \"10.0.0.0/16\" unless you know what you're doing. Default value: \"10.0.0.0/16\"")
    
    # # EC2 
    # parser.add_argument("-lfs-c-ags-it", "--lfs-client-auto-scaling-group-instance-type", dest = "lfs_client_ags_it", type = str, default = "r5.4xlarge", help = "The EC2 instance type to use for the λFS client auto-scaling group. Default: \"r5.4xlarge\"")
    # parser.add_argument("-hfs-c-ags-it","--hopsfs-client-auto-scaling-group-instance-type", dest = "hopsfs_client_ags_it", type = str, default = "r5.4xlarge", help = "The EC2 instance type to use for the HopsFS client auto-scaling group. Default: \"r5.4xlarge\"")
    # parser.add_argument("-hfs-nn-ags-it","--hopsfs-namenode-auto-scaling-group-instance-type", dest = "hopsfs_namenode_ags_it", type = str, default = "r5.4xlarge", help = "The EC2 instance type to use for the HopsFS NameNode auto-scaling group. Default: \"r5.4xlarge\"")
    # parser.add_argument("--num-ndb-datanodes", dest = "num_ndb_datanodes", type = int, default = 4, help = "The number of MySQL NDB Data Nodes to create. Default: 4")
    # parser.add_argument("--ndb-manager-node-instance-type", dest = "ndb_manager_instance_type", default = "r5.4xlarge", type = str, help = "Instance type to use for the MySQL NDB Manager Node. Default: \"r5.4xlarge\"")
    # parser.add_argument("--ndb-data-node-instance-type", dest = "ndb_datanode_instance_type", default = "r5.4xlarge", type = str, help = "Instance type to use for the MySQL NDB Data Node(s). Default: \"r5.4xlarge\"")
    # parser.add_argument("--lambdafs-zk-instance-type", dest = "lambdafs_zk_instance_type", default = "r5.4xlarge", type = str, help = "Instance type to use for the LambdaFS ZooKeeper node(s) instance type.")
    # parser.add_argument("--lambdafs-client-vm-instance-type", dest = "lfs_client_vm_instance_type", default = "r5.4xlarge", type = str, help = "Instance type to use for the 'primary' λFS client VM, which also doubles as the experiment driver. Default: \"r5.4xlarge\"")
    # parser.add_argument("--hopsfs-client-vm-instance-type", dest = "hopsfs_client_vm_instance_type", default = "r5.4xlarge", type = str, help = "Instance type to use for the 'primary' HopsFS client VM, which also doubles as the experiment driver. Default: \"r5.4xlarge\"")
    # parser.add_argument("--num-lambdafs-zookeeper-vms", dest = "num_lambda_fs_zk_vms", default = 3, type = int, help = "The number of λFS ZooKeeper VMs to create. Default: 3")
    
    # # parser.add_argument("-start-zk", "--start-zoo-keeper", dest = "start_zoo_keeper", action = "store_true", help = "If passed, also start associated ZooKeeper on the VMs. Note that, if you simply opt to create the ZooKeeper VMs, the VMs will start running. But ZooKeeper itself won't be started unless you pass this argument.")
    # # parser.add_argument("--start-ndb", dest = "start_ndb", action = "store_true", help = "If passed, also start NDB on the associated VMs. Note that, if you simply opt to create the NDB VMs, the VMs will start running. But NDB itself won't be started unless you pass this argument.")
    
    # # EKS.
    # parser.add_argument("--eks-cluster-name", dest = "eks_cluster_name", type = str, default = "lambda-fs-eks-cluster", help = "The name to use for the AWS EKS cluster. We deploy the FaaS platform OpenWhisk on this EKS cluster. Default: \"lambda-fs-eks-cluster\"")
    # parser.add_argument("--eks-iam-role-name", dest = "eks_iam_role_name", type = str, default = "lambda-fs-eks-cluster-role", help = "The name to either use when creating the new IAM role for the AWS EKS cluster, or this is the name of an existing role to use for the cluster (when you also pass the '--skip-eks-iam-role-creation' argument).")
    return parser.parse_args()

def main():
    global NO_COLOR
    
    command_line_args = get_args() 
    
    log_success("Welcome to the λFS Interactive Setup.")
    log_warning("Before you continue, please note that many of the components required by λFS (and HopsFS) cost money.")
    log_warning("AWS will begin charging you for these resources as soon as they are created.")
    print()
    print()
    
    using_yaml = False 
    
    # Keep track of instance IDs and whatnot so we can find them later.
    data = dict() 
    
    if command_line_args.yaml is not None:
        using_yaml = True 
        with open(command_line_args.yaml, "r") as stream:
            logger.info("Loading arguments from YAML file located at \"%s\"" % command_line_args.yaml)
            try:
                arguments = yaml.safe_load(stream)
                log_success("Loaded %s arguments from YAML file." % len(arguments))
            except yaml.YAMLError as exc:
                log_error("Failed to load arguments from YAML file \"%s\"." % command_line_args.yaml)
                log_error("Error: %s" % str(exc))
                exit(1) 
            
            NO_COLOR = arguments.get("no_color", False)
            aws_profile_name = arguments.get("aws_profile", None)
            aws_region = arguments.get("aws_region", "us-east-1")
            user_public_ip = arguments.get("user_public_ip", "DEFAULT_VALUE")
            vpc_name = arguments.get("vpc_name", "LambdaFS_VPC")
            vpc_cidr_block = "10.0.0.0/16" 
            
            security_group_name = arguments.get("security_group_name", "lambda-fs-security-group")
            eks_cluster_name = arguments.get("eks_cluster_name ", "lambda-fs-eks-cluster")
            eks_iam_role_name = arguments.get("eks_iam_role_name", "lambda-fs-eks-cluster-role")
            
            ssh_keypair_name = arguments.get("ssh_keypair_name", None)
            ssh_key_path = arguments.get("ssh_key_path", None)
            num_ndb_datanodes = arguments.get("num_ndb_datanodes", 4)
            num_lambda_fs_zk_vms = arguments.get("num_lambda_fs_zk_vms", 3)
            
            lfs_client_ags_it = arguments.get("lfs_client_autoscaling_group_instance_type", "r5.4xlarge")
            hopsfs_client_ags_it = arguments.get("hopsfs_client_autoscaling_group_instance_type", "r5.4xlarge")
            hopsfs_namenode_ags_it = arguments.get("hopsfs_namenode_autoscaling_group_instance_type", "r5.4xlarge")
            lfs_client_vm_instance_type = arguments.get("lfs_client_vm_instance_type", "r5.4xlarge")
            ndb_manager_instance_type = arguments.get("ndb_manager_instance_type", "r5.4xlarge")
            ndb_datanode_instance_type = arguments.get("ndb_datanode_instance_type", "r5.4xlarge")
            lambdafs_zk_instance_type = arguments.get("lambdafs_zk_instance_type", "r5.4xlarge")
            hopsfs_client_vm_instance_type = arguments.get("hopsfs_client_vm_instance_type", "r5.4xlarge")
            
            do_create_lambda_fs_client_vm = arguments.get("create_lambda_fs_client_vm", True)
            do_create_hops_fs_client_vm = arguments.get("create_hops_fs_client_vm", True)
            
            skip_iam_role_creation = arguments.get("skip_iam_role_creation", False)
            skip_vpc_creation = arguments.get("skip_vpc_creation", False)
            skip_eks = arguments.get("skip_eks", False)
            skip_ndb = arguments.get("skip_ndb", False)
            skip_zookeeper = arguments.get("skip_zookeeper", False)
            skip_launch_templates = arguments.get("skip_launch_templates", False)
            skip_autoscaling_groups = arguments.get("skip_autoscaling_groups", False)
            
            zookeeper_jvm_heap_size = arguments.get("zookeeper_jvm_heap_size", 4000)
            
            # start_zookeeper = arguments.get("start_zoo_keeper", False)
            # start_ndb = arguments.get("start_ndb", False)
            
            if ssh_key_path == None and (not skip_ndb or not skip_zookeeper or do_create_lambda_fs_client_vm or do_create_hops_fs_client_vm):
                log_error("The SSH key path cannot be None.")
                exit(1)
                
            if ssh_keypair_name == None and (not skip_ndb or not skip_zookeeper or do_create_lambda_fs_client_vm or do_create_hops_fs_client_vm):
                log_error("The SSH keypair name cannot be None.")
                exit(1)
    else:
        log_error("Please specify the path to the YAML configuration file.")
        exit(1) 
        # NO_COLOR = command_line_args.no_color
        # aws_profile_name = command_line_args.aws_profile
        # aws_region = command_line_args.aws_region
        # user_public_ip = command_line_args.user_public_ip
        # vpc_name = command_line_args.vpc_name
        # vpc_cidr_block = "10.0.0.0/16" # command_line_args.vpc_cidr_block
        # security_group_name = command_line_args.security_group_name
        # eks_cluster_name = command_line_args.eks_cluster_name 
        # skip_iam_role_creation = command_line_args.skip_iam_role_creation
        # eks_iam_role_name = command_line_args.eks_iam_role_name
        # ssh_keypair_name = command_line_args.ssh_keypair_name
        # num_ndb_datanodes = command_line_args.num_ndb_datanodes
        # num_lambda_fs_zk_vms = command_line_args.num_lambda_fs_zk_vms
        # ndb_manager_instance_type = command_line_args.ndb_manager_instance_type
        # ndb_datanode_instance_type = command_line_args.ndb_datanode_instance_type
        # lambdafs_zk_instance_type = command_line_args.lambdafs_zk_instance_type
        # skip_vpc_creation = command_line_args.skip_vpc_creation
        # skip_eks = command_line_args.skip_eks
        # lfs_client_ags_it = command_line_args.lfs_client_ags_it
        # hopsfs_client_ags_it = command_line_args.hopsfs_client_ags_it
        # hopsfs_namenode_ags_it = command_line_args.hopsfs_namenode_ags_it
        # lfs_client_vm_instance_type = command_line_args.lfs_client_vm_instance_type
        # hopsfs_client_vm_instance_type = command_line_args.hopsfs_client_vm_instance_type
        # skip_ndb = command_line_args.skip_ndb
        # do_create_lambda_fs_client_vm = command_line_args.create_lambda_fs_client_vm
        # do_create_hops_fs_client_vm = command_line_args.create_hops_fs_client_vm
        # skip_launch_templates = command_line_args.skip_launch_templates
        # skip_autoscaling_groups = command_line_args.skip_autoscaling_groups
        # skip_zookeeper = command_line_args.skip_zookeeper
        # ssh_key_path = command_line_args.ssh_key_path
        # start_zookeeper = command_line_args.start_zookeeper
        # start_ndb = command_line_args.start_ndb
    
    if user_public_ip == "DEFAULT_VALUE":
        log_warning("Attempting to resolve your IP address automatically...")
        try:
            user_public_ip = get('https://api.ipify.org', timeout = 5).content.decode('utf8')
            log_success("Successfully resolved your IP address.")
            print()
        except (requests.exceptions.ReadTimeout, urllib3.exceptions.ReadTimeoutError):
            log_error("Could not connect to api.ipify.org to resolve your IP address. Please pass your IP address to this script directly to continue.")
            exit(1)
    
    try:
        socket.inet_aton(user_public_ip)
    except OSError:
        log_error("Invalid user IP address: \"%s\"" % user_public_ip)
        exit(1) 
    
    if aws_profile_name == None:
        log_warning("AWS profile == None.")
        log_warning("If you are unsure what profile to use, you can list the available profiles on your device via the 'aws configure list-profiles' command.")
        log_warning("Execute that command ('aws configure list-profiles') in a terminal or command prompt session to view a list of the available AWS CLI profiles.")
        log_warning("For now, we will use the default profile.")
    else:
        logger.info("Selected AWS profile: \"%s\"" % aws_profile_name)

    
    print()
    print()
    print()
    log_important("Please verify that the following information is correct before continuing.")
    print()
    
    if using_yaml:
        for arg_name, arg_value in arguments.items():
            logger.info("{:50s}= \"{}\"".format(arg_name, str(arg_value)))
    else:
        for arg in vars(command_line_args):
            logger.info("{:50s}= \"{}\"".format(arg, str(getattr(command_line_args, arg))))
    
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
    
    session:boto3.Session = None 
    if aws_profile_name is not None:
        logger.info("Attempting to create AWS Session using explicitly-specified credentials profile \"%s\" now..." % aws_profile_name)
        try:
            session = boto3.Session(profile_name = aws_profile_name)
            log_success("Successfully created boto3 Session using AWS profile \"%s\"" % aws_profile_name)
        except Exception as ex: 
            log_error("Exception encountered while trying to use AWS credentials profile \"%s\"." % aws_profile_name)
            raise ex 
        ec2_client = session.client('ec2', region_name = aws_region)
        ec2_resource = session.resource('ec2', region_name = aws_region)
        autoscaling_client = session.client("autoscaling", region_name = aws_region)
    else:
        ec2_client = boto3.client('ec2', region_name = aws_region)
        ec2_resource = boto3.resource('ec2', region_name = aws_region)
        autoscaling_client = boto3.client("autoscaling", region_name = aws_region)

    if not validate_keypair_exists(ssh_keypair_name = ssh_keypair_name, ec2_client = ec2_client):
        log_error("Could not find SSH keypair named \"%s\" registered with AWS." % ssh_keypair_name)
        log_error("Please verify that the given keypair exists, is registered with AWS, and has no typos in its name.")
        exit(1)


    data["aws_region"] = aws_region 
    data["user_public_ip"] = user_public_ip
    data["vpc_name"] = vpc_name 

    vpc_id:str = None 
    if not skip_vpc_creation:
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
        
        data["security_group_name"] = security_group_name
        data["vpc_id"] = vpc_id
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
                        
                if name_of_vpc == None:
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
        
        data["vpc_id"] = vpc_id
            
    log_success("Resolved VPC ID of VPC \"%s\" as %s" % (vpc_name, vpc_id))
        
    if not skip_eks:
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
    
    data["security_group_ids"] = security_group_ids
    
    create_launch_templates_and_instance_groups(
        ec2_client = ec2_client,
        autoscaling_client = autoscaling_client,
        security_group_ids = security_group_ids,
        lfs_client_ags_it = lfs_client_ags_it,
        hopsfs_client_ags_it = hopsfs_client_ags_it,
        hopsfs_namenode_ags_it = hopsfs_namenode_ags_it,
        skip_launch_templates = skip_launch_templates,
        skip_autoscaling_groups = skip_autoscaling_groups,
        data = data
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
    
    data['subnet_ids'] = subnet_ids
    data['public_subnet_ids'] = public_subnet_ids
    data['private_subnet_ids'] = private_subnet_ids
    
    if not skip_ndb:
        logger.info("Creating the MySQL NDB cluster nodes now.")
        ndb_resp = create_ndb(
            ec2_resource = ec2_resource, 
            ssh_keypair_name = ssh_keypair_name, 
            num_datanodes = num_ndb_datanodes, 
            security_group_ids = security_group_ids,
            subnet_id = public_subnet_ids[0],
            ndb_manager_instance_type = ndb_manager_instance_type,
            ndb_datanode_instance_type = ndb_datanode_instance_type)
        
        log_success("Created NDB Manager Node: %s" % ndb_resp["manager-node-id"])
        log_success("Created %d NDB Data Node(s): %s" % (len(ndb_resp["data-node-ids"]), str(ndb_resp["data-node-ids"])))
        
        data.update(ndb_resp)
    
    if not skip_zookeeper:
        logger.info("Creating the λFS ZooKeeper nodes now.")
        zk_node_IDs = create_lambda_fs_zookeeper_vms(
            ec2_resource = ec2_resource, 
            ssh_keypair_name = ssh_keypair_name, 
            num_vms = num_lambda_fs_zk_vms, 
            security_group_ids = security_group_ids,
            subnet_id = public_subnet_ids[0],
            instance_type = lambdafs_zk_instance_type)
        log_success("Created %d ZooKeeper node(s): %s" % (len(zk_node_IDs), str(zk_node_IDs)))
        
        data["zk_node_IDs"] = zk_node_IDs
        
        logger.info("Sleeping for 30 seconds so that ZooKeeper VMs can start.")
        for _ in tqdm(range(121)):
            sleep(0.25)
        
        logger.info("Updating ZooKeeper configuration now.")
        zk_node_public_IPs = update_zookeeper_config(ec2_client = ec2_client, instance_ids = zk_node_IDs, ssh_key_path = ssh_key_path, zookeeper_jvm_heap_size = zookeeper_jvm_heap_size, data = data)
        
        logger.info("Starting ZooKeeper now.")
        start_zookeeper_cluster(ips = zk_node_public_IPs, ssh_key_path = ssh_key_path)
        
        log_success("Successfully started the ZooKeeper cluster. Sleeping for a few seconds, then populating ZK cluster.")
        for _ in tqdm(range(21)):
            sleep(0.25)
        
        logger.info("Populating ZooKeeper cluster now.")
        populate_zookeeper(ips = zk_node_public_IPs, ssh_key_path = ssh_key_path)
    
    if do_create_lambda_fs_client_vm:
        logger.info("Creating λFS client virtual machine.")
        lambda_fs_primary_client_vm_id = create_lambda_fs_client_vm(ec2_resource = ec2_resource, ssh_keypair_name = ssh_keypair_name, instance_type = lfs_client_vm_instance_type, subnet_id = public_subnet_ids[0], security_group_ids = security_group_ids)
        log_success("Created λFS client virtual machine: %s" % lambda_fs_primary_client_vm_id)
        
        data["lambda_fs_primary_client_vm_id"] = lambda_fs_primary_client_vm_id
        
    if do_create_hops_fs_client_vm:
        logger.info("Creating HopsFS client virtual machine.")
        hops_fs_primary_client_vm_id = create_hops_fs_client_vm(ec2_resource = ec2_resource, ssh_keypair_name = ssh_keypair_name, instance_type = hopsfs_client_vm_instance_type, subnet_id = public_subnet_ids[0], security_group_ids = security_group_ids)
        log_success("Created HopsFS client virtual machine: %s" % hops_fs_primary_client_vm_id)
        
        data["hops_fs_primary_client_vm_id"] = hops_fs_primary_client_vm_id
    
    current_datetime = str(datetime.now())
    current_datetime = current_datetime.replace(":", "_")
    
    logger.info("Newly created AWS infrastrucutre:")
    for k,v in data.items():
        logger.info("%s: %s" % (k, str(v)))
    
    with open("./infrastructure_ids_%s_compat.json" % current_datetime, "w") as f:
        json.dump(data, f)

    with open("./infrastructure_ids_%s.json" % current_datetime, "w", encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

if __name__ == "__main__":
    main()