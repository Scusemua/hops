    # Defaults to the user making the request.
    response = iam.get_user() 
    
    # Make sure we got a valid response.
    if response is None or 'User' not in response:
        log_error("Expected IAM::GetUser response to contain key \"User\".")
        log_error("IAM::GetUser response: %s" % str(response))
        exit(1)
    
    iam_user_name = response['User']['UserName']
    iam_user_arn  = response['User']['Arn']
    
    # Make sure we got a valid ARN.
    if iam_user_arn == None:
        log_error("Expected IAM::GetUser response to contain valid ARN.")
        log_error("IAM::GetUser response: %s" % str(response))
        exit(1)
    
    # Make sure we got a valid username.
    if iam_user_name == None:
        log_error("Expected IAM::GetUser response to contain valid user name.")
        log_error("IAM::GetUser response: %s" % str(response))
        exit(1)

    logger.info("Current IAM UserName: %s" % iam_user_name)
    logger.info("Current IAM ARN: %s" % iam_user_arn)
   
    AssumeRolePolicyDocument = {
        "Version": "2023-9-27",
        "Statement": [{
            "Sid": "PermissionToAssumeRole",
            "Effect": "Allow",
            "Action": [
                "sts:AssumeRole"
            ],
            "Resource": iam_user_arn
        }]
    }
    
    # TODO: Give this a value.
    iam_role_name = None 
    
    try:
        role_response = iam.create_role(
            RoleName = "PermissionToAssumeRole", Description = "description", AssumeRolePolicyDocument = json.dumps(AssumeRolePolicyDocument)) 
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
    iam.attach_role_policy(
        PolicyArn = 'arn:aws:iam::aws:policy/AWSXrayWriteOnlyAccess',
        RoleName = iam_role_name)
    iam.attach_role_policy(
        PolicyArn = 'arn:aws:iam::aws:policy/AmazonS3FullAccess',
        RoleName = iam_role_name)
    iam.attach_role_policy(
        PolicyArn = 'arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole',
        RoleName = iam_role_name)   