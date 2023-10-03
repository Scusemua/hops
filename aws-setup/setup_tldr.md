# Setup - TLDR Edition

This version provides the exact steps/commands required to setup the required infrastructure. This document assumes you will be making use of the provided scripts, namely `create_aws_infrastructure.py` and `configure_eks_cluster.sh`. 

## Step 1

Install and configure the AWS CLI. Please refer to the [general AWS CLI documentation](https://aws.amazon.com/cli/), [installation instructions](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html), and [credentials configuration instructions](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html) for this step.

## Step 2

Install the Python modules listed in the `aws-setup/requirements.txt` field. This can be performed in a single step using the `pip` module:

```
python3 -m pip install -r requirements.txt
```

(You may need to adjust the command above depending on how you invoke python/pip.)

## Step 2

Create a `config.yaml`, using the `sample_config.yaml` as a reference. Provide values for the `ssh_keypair_name`, `ssh_key_path`, and `aws_profile` configuration parameters as described in `setup.md`. 

Once your configuration file has been created and is located within the `aws-setup/` directory, execute the `create_aws_infrastructure.py` script using `Python 3`. We tested this script on Windows 10 version 22H2 (OS Build 19045.3448) with Python 3.9.4 (tags/v3.9.4:1f2e308, Apr  6 2021, 13:40:21).

## Step 3

Execute the `create_aws_infrastructure.py` script as follows:

```
python3 create_aws_infrastructure.py --yaml ./config.yaml
```

## Step 4 

Wait 10 - 15 minutes until the newly-created AWS EKS cluster becomes operational. Once the cluster has become operational, execute the `configure_eks_cluster.sh` script, passing in the required arguments as follows:

```
configure_eks_cluster.sh <arg1> <arg2> <arg3>
```

This script will install the Amazon EBS CSI Driver, which is required by OpenWhisk.