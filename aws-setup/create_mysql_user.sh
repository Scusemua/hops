# This is typically called from the `create_aws_infrastructure.py` script.
# The first argument is the public IPv4 address of the manager node VM.
# The second argument is the path to the key file.
ssh -i $2 -o "StrictHostKeyChecking no" ubuntu@$1 <<'ENDSSH'
sudo /usr/local/mysql/bin/mysql
CREATE USER 'user'@'%' IDENTIFIED BY '123password123';
GRANT ALL PRIVILEGES ON *.* TO 'user'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
quit;
ENDSSH