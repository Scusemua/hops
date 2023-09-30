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

from time import sleep
from tqdm import tqdm
from requests import get
from paramiko.client import SSHClient, AutoAddPolicy
from paramiko.rsakey import RSAKey

ec2_client = boto3.client("ec2")

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(formatter)
logger.addHandler(ch)

instance_ids = ['i-0c84ad43adb739556', 'i-03c5508cc05abe3d2', 'i-02b169ce7f431bae1']

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

instance_private_dns_names = ["ip-10-0-22-153.ec2.internal", "ip-10-0-26-98.ec2.internal", "ip-10-0-18-74.ec2.internal"]
for i,private_dns_name in enumerate(instance_private_dns_names):
    config = config + ("server.%d=%s:2888:3888" % (i, private_dns_name)) + "\n"

logger.info("Configuration file:\n%s" % str(config))

key = RSAKey(filename = ssh_key_path)

for i,ip in enumerate(instance_public_ips):
    ssh_client = SSHClient()
    ssh_client.set_missing_host_key_policy(AutoAddPolicy)
    logger.info("Connecting to ZooKeeper VM at %s" % ip)
    ssh_client.connect(hostname = ip, port = 22, username = "ubuntu", pkey = key)
    logger.info("Connected!")
    
    sftp_client = ssh_client.open_sftp()
    file = sftp_client.open("/home/ubuntu/zk/conf/zoo.cfg", mode = "w")
    
    file.write(config)
    file.close()
    
    ssh_client.exec_command("echo %d > /data/zookeeper/myid" % i)
    
    ssh_client.close()