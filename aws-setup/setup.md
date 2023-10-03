# AWS Setup 

The following document provides a set of directions for creating the required AWS infrastructure to deploy and run $\lambda$FS and HopsFS. Much of this process can be automated using the `create_aws_infrastructure.py` and `configure_eks_cluster.sh` scripts. The `configure_eks_cluster.sh` script should be executed once the AWS EKS cluster created by the `create_aws_infrastructure.py` script becomes operational. 

Please note that the `setup_tldr.md` document provides an abridged version of these instructions. 

# Requirements

This section outlines requirements and prerequisites for following these instructions. 

## Software

We tested these scripts on Windows 10 version 22H2 (OS Build 19045.3448) with Python 3.9.4 (tags/v3.9.4:1f2e308, Apr  6 2021, 13:40:21).

The `aws-setup/requirements.txt` includes a list of all required Python modules as used by the `create_aws_infrastructure.py` script. The version numbers explicitly listed in the `requirements.txt` file are the versions we had installed when creating and using the script. If you have more recent versions of any of the modules and the script does not work, then please try downgrading to the version numbers explicitly listed in the `requirements.txt` file. 

You must install and configure the `AWS CLI`. Please refer to the [general AWS CLI documentation](https://aws.amazon.com/cli/), [installation instructions](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html), and [credentials configuration instructions](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html) for this step.

You must install and configure `kubectl`, the Kubernetes command-line tool, which allows you to run commands against Kubernetes clusters. Please refer to the [official Kubernetes documentation](https://kubernetes.io/docs/tasks/tools/) for this step.

## Required Manual Configuration

The default values for most parameters will be sufficient. There are a few that must be specified explicitly. These include:
- `ssh_keypair_name`: In order to be able to connect to the various virtual machines used by $\lambda$FS and HopsFS, you will need to create and register an *EC2 key pair* with AWS. (If you have already done so, then you may reuse an existing key pair, provided the key is an RSA key.) [See this documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html) from AWS concerning "Amazon EC2 key pairs and Linux instances" for additional details. 
- `ssh_key_path`: This is a path to the private key of the EC2 key pair specified in the `ssh_keypair_name` parameter. **This must be an RSA key.**
- `aws_profile` (possibly): Depending on how you've configured the AWS credentials on your computer, you may be able to simply use the default AWS credentials profile. If you've not configured any AWS credentials on your computer, then this can be done by installing the [AWS CLI](https://aws.amazon.com/cli/). See [this AWS documentation](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html) concerning "configuration and credential file settings" for more details.

Copying the `sample_config.yaml` file to a `config.yaml` file and using the default values for all other configurations parameters (aside from the parameters explicitly listed above) should be sufficient for creating all of the necessary components.

The `create_aws_infrastructure.py` script will automatically provision the following components:

- AWS Virtual Private Cloud (VPC)
- Security group
- Public & private subnets 
- EC2 virtual machines for:
  - MySQL NDB Cluster (used by both HopsFS and $\lambda$FS)
    - The manager node and however many data nodes
  - "Primary" client VMs (which serve as experiment drivers) for HopsFS and $\lambda$FS
  - ZooKeeper nodes used by $\lambda$FS
- Launch templates for $\lambda$FS clients, HopsFS clients, and HopsFS NameNodes. 
- Auto-scaling groups for $\lambda$FS clients, HopsFS clients, and HopsFS NameNodes.
- AWS Elastic Kubernetes Service (EKS) cluster, onto which we deploy OpenWhisk, the FaaS platform used by $\lambda$FS.
  - The script also creates a number of other componets required by the AWS EKS cluster, including an IAM role, service accounts, etc.

The script can be configured by creating a `config.yaml` file within the same directory as the script (i.e., the `aws-setup/` directory). There is a `sample_config.yaml` provided with explanations of the various configuration parameters. 

If you are interested in manually deploying or configuring your VPC, the `Networking` section of the `AWS Elastic Kubernetes Service (EKS)` instructions provides information about what is required in the VPC.

# AWS Elastic Kubernetes Service (EKS)

The AWS EKS cluster used by $\lambda$FS can be created automatically using both the `create_aws_infrastructure.py` and `configure_eks_cluster.sh` scripts. As described above, the `configure_eks_cluster.sh` script should be executed once the AWS EKS cluster created by the `create_aws_infrastructure.py` script becomes operational. 

Nevertheless, we have found it to be a little tricky to deploy OpenWhisk on AWS EKS. The following are some useful resources concerning the creation of an AWS EKS cluster and the subsequent deployment of OpenWhisk onto the AWS EKS cluster:

- [Official OpenWhisk Documentation: "Deploying OpenWhisk on Amazon EKS"](https://github.com/apache/openwhisk-deploy-kube/blob/master/docs/k8s-aws.md). 
  - In particular, you should follow the ["Configuring OpenWhisk using SSL and IAM"](https://github.com/apache/openwhisk-deploy-kube/blob/master/docs/k8s-aws.md#configuring-openwhisk-using-ssl-and-iam) section. We also use the configuration described in the ["Configuring Openwhisk using SSL and Elastic Loadbalancers"](https://github.com/apache/openwhisk-deploy-kube/blob/master/docs/k8s-aws.md#configuring-openwhisk-using-ssl-and-iam) section; however, you can still use self-signed certificates if you are simply looking to test and experiment with $\lambda$FS (which is *not* what their documentation says).
- [Amazon EBS CSI driver](https://docs.aws.amazon.com/eks/latest/userguide/ebs-csi.html). You will need to install the Amazon EBS CSI driver on your Amazon EKS cluster in order for OpenWhisk to work. The deployment script (`create_aws_infrastructure.py`) *should* perform this step for you automatically; however, if the script encounters any issues, then you can simply follow the AWS documentation to manually install the Amazin EBS CSI driver. We will also include our own instructions below, as supplementary material. 

## Manual Creation/Deployment Instructions

### **General Configuration**

You can manually create and deploy the AWS EKS cluster using either the AWS Web Console or the AWS Command Line Interface (CLI). The following instructions will be agnostic to the method you elect to use; the instructions will simply specify the required configuration.

You may name the AWS EKS cluster whatever you'd like. We will use `"LambdaFS_EKS_Cluster"`.

The `Kubernetes version` should be specified as 1.24, as this is what $\lambda$FS was developed on. Other versions of Kubernetes may work fine, but we've not tested them with $\lambda$FS ourselves. 

You must create an IAM role to serve as the "Amazon EKS cluster role". Please follow the [instructions in the official AWS documentation](https://docs.aws.amazon.com/eks/latest/userguide/service_IAM_role.html#create-service-role) concerning this step. We will refer to this role by name as `eksClusterRole`. 

### **Networking (VPC)**

Please specify the VPC created using the `create_aws_infrastructure.py` script. If you create the VPC yourself, then you must create the following components within that VPC:
- Security group (which we will refer to by name as `lambda-fs-security-group`).
  - The security group should have a rule of type `All traffic` (`All` protocols, `All` port range) whose `Source` is the security group itself.
  - The seceurity group should have *another* rule of type `SSH` (`TCP` protocol, port range `22`) whose `Source` is the IP address from which you'd like to SSH into VMs residing within the VPC. 
- Internet gateway
- Two "public" subnets with routes to the internet gateway. The `destination` of the routes should be `0.0.0.0/0`, and the `target` is the ID of the internet gateway. 
- NAT gateway (deployed in one of the public subnets)
- Two "private" subnets, both of which have a route to the NAT gateway. The `destination` of the routes should be `0.0.0.0/0`, and the `target` is the ID of the NAT gateway. 
- We set the `IPv4` of the VPC to `10.0.0.0/16`. 

For the `subnets` of your AWS EKS cluster, you should specify all of the subnets in your VPC. If you created your VPC using the `create_aws_infrastructure.py` script or manually created the VPC using the same configuration (i.e., the configuration specified in the bulleted list above), then select the two private subnets and the two public subnets. 

You should select the security group created during the VPC creation for the AWS EKS cluster.

Select `IPv4` for the `cluster IP address family`.

For `Cluster endpoint access`, select `Public`. 

There is no logging that must be configured. If you are performing this step using the AWS web console, then this means that you can skip the `Configure logging` step. For cluster add-ons, we are using `CoreDNS`, `kube-proxy`, and `Amazon VPC CNI`. These should be selected by-default when using the AWS web console to create the EKS cluster. We use the default settings (in the web console, at least) for these add-ons. 

After creating your AWS EKS cluster, it may take 10 - 15 minutes for the cluster to become operational. Once the cluster becomes operational, there are some additional steps that must be taken before deploying OpenWhisk. 

### **Amazon EBS CSI Driver**

#### **Overview**

The Amazon Elastic Block Store (Amazon EBS) Container Storage Interface (CSI) driver manages the lifecycle of Amazon EBS volumes as storage for the Kubernetes Volumes that you create. This component is required in order for OpenWhisk to be deployed successfully.

AWS provides its own documentation for installing the Amazon EBS CSI driver onto an AWS EKS cluster. This documentation can be found [here](https://docs.aws.amazon.com/eks/latest/userguide/ebs-csi.html). In our experience, the documentation sufficiently covers the installation process. We highly recommend deploying a simple, sample application and verify that the CSI driver is working *before* attempting to deploy OpenWhisk onto your AWS EKS cluster. AWS provides such a sample documentation [here](https://docs.aws.amazon.com/eks/latest/userguide/ebs-sample-app.html) (along with instructions on how to setup and teardown the sample app).

#### **Installation Tips & Hints**

**Creating the Amazon EBS CSI driver IAM role**

The Amazon EBS CSI plugin requires IAM permissions to make calls to AWS APIs on your behalf. In order to perform this part of the installation process, you must have an existing AWS EKS cluster and an existing AWS Identity and Access Management (IAM) OpenID Connect (OIDC) provider for your cluster. If you are unsure as to whether or not you have one -- or if you know that you need to create one -- please see the following resource: ["creating an IAM OIDC provider for your cluster"](https://docs.aws.amazon.com/eks/latest/userguide/enable-iam-roles-for-service-accounts.html).

**IMPORTANT:** Once you've installed the Amazon EBS CSI driver, there is an additional step that you should perform. Specifically, you should annotate the associated Kubernetes service account with the ARN of the EKS cluster IAM role. (This role was either created automatically via the `create_aws_infrastructure.py` script, or you created it while creating the AWS EKS cluster.)

To annotate the service account, please execute the following command, making sure to replace `111122223333` with your [account ID](https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-identifiers.html) and `AmazonEKS_EBS_CSI_DriverRole` with the name of the IAM role:

```
kubectl annotate serviceaccount ebs-csi-controller-sa \
    -n kube-system \
    eks.amazonaws.com/role-arn=arn:aws:iam::111122223333:role/AmazonEKS_EBS_CSI_DriverRole
```

Also, if you find you are still having errors, then you may need to modify the `EKS Cluster IAM role` such that it has the `sts:AssumeRoleWithWebIdentity` action specified in its trust policy/trust relationship. However, this itself may cause issues/errors (apparently?), so you should only add the `sts:AssumeRoleWithWebIdentity` action if you have reason to think you need to. (For example, you attempt to deploy the sample app used to determine if the EBS CSI driver is working. Upon describing the Kubernetes pod created by the app, you see errors stating that it is not authorized to perform some action and explicitly mentions `sts:AssumeRoleWithWebIdentity`.)

### **OpenWhisk NGINX Secret** 

You may encounter an error when deploying OpenWhisk (which we've not yet gone over in these instructions) concerning OpenWhisk's `gencerts` pod. This pod attempts to either use an existing "secret" called `<openwhisk-deployment-name>-nginx` or create a new one if no secret with that name exists. The creation process can sometimes fail with an error like the following (`testdev` is the name given to the OpenWhisk deployment):

```
Error from server (NotFound): secrets "testdev-nginx" not found
generating new testdev-nginx secret
generating server certificate request
Can't load /root/.rnd into RNG
139693137723840:error:2406F079:random number generator:RAND_load_file:Cannot open file:../crypto/rand/randfile.c:88:Filename=/root/.rnd
problems making Certificate Request
139693137723840:error:0D07A097:asn1 encoding routines:ASN1_mbstring_ncopy:string too long:../crypto/asn1/a_mbstr.c:107:maxsize=64
```

To avoid this, you can simply pre-create the `<openwhisk-deployment-name>-nginx` secret *before* attempting to deploy OpenWhisk. This process is performed automatically by the `configure_eks_cluster.sh` script; however, if you are setting up the AWS EKS cluster manually, then you will (likely) need to perform this step yourself. If you elect to skip this step and deploy OpenWhisk without pre-creating the secret, and you ultimately encounter the error, then simply perform `helm uninstall <deployment-name>` to uninstall OpenWhisk from your Kubernetes cluster. Then, follow the steps here before trying again to deploy OpenWhisk. 

#### **Creating NGINX Secret**

Generate the certificate and key (replace `KEY` and `CERT` with whatever you want the generated files to be named):

```
openssl req -x509 -newkey rsa:4096 -keyout KEY.pem -out CERT.pem -sha256 -days 365 -nodes
```

Next, create the `secret`. The secret must be named `"<OpenWhisk-deployment-name>-nginx"`. The name of the OpenWhisk deployment is whatever you specify to `helm` when deploying the OpenWhisk chart via `helm install <deployment_name> values.yaml .` (as described later in the documentation). Once again, replace `KEY` and `CERT` with whatever you specified when generating the files:

```
kubectl create secret tls OPENWHISK_DEPLOYMENT_NAME-nginx --cert=CERT.pem --key=KEY.pem
```

If you named your OpenWhisk deployment `owdev`, then the command would be:

```
kubectl create secret tls owdev-nginx --cert=CERT.pem --key=KEY.pem
```

## Common Issues & Errors

In this section, we describe some commonly-encountered problems (and their solutions) when creating the AWS EKS cluster and deploying OpenWhisk onto it. 

### **ERROR: "Your current IAM principal doesn’t have access to Kubernetes objects on this cluster."**

You may see this error message displayed at the top of the AWS Web Console when viewing your AWS EKS cluster. In order to resolve this error, please follow the instructions outlined in the [Amazon EKS "View Kubernetes resources" documentation](https://docs.aws.amazon.com/eks/latest/userguide/view-kubernetes-resources.html#view-kubernetes-resources-permissions). 

This documentation mentions ensuring that the proper permissions are assigned "to the IAM principal that you're using." 

### **Failure to Generate NGINX Secret When Deploying OpenWhisk**

You may encounter an error when deploying OpenWhisk (which we've not yet gone over in these instructions) concerning OpenWhisk's `gencerts` pod. This pod attempts to either use an existing "secret" called `<openwhisk-deployment-name>-nginx` or create a new one if no secret with that name exists. The creation process can sometimes fail with an error like the following (`testdev` is the name given to the OpenWhisk deployment):

```
Error from server (NotFound): secrets "testdev-nginx" not found
generating new testdev-nginx secret
generating server certificate request
Can't load /root/.rnd into RNG
139693137723840:error:2406F079:random number generator:RAND_load_file:Cannot open file:../crypto/rand/randfile.c:88:Filename=/root/.rnd
problems making Certificate Request
139693137723840:error:0D07A097:asn1 encoding routines:ASN1_mbstring_ncopy:string too long:../crypto/asn1/a_mbstr.c:107:maxsize=64
```

The steps to avoid/resolve this error are described above in the "**OpenWhisk NGINX Secret**" section.