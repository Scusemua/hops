# This is typically called from the `create_aws_infrastructure.py` script.
# The first argument is the public IPv4 address of the data node VM.
# The second argument is the path to the key file.
ssh -i $2 -o "StrictHostKeyChecking no" ubuntu@$1 <<'ENDSSH'
sudo /usr/local/bin/ndbmtd --initial
ENDSSH