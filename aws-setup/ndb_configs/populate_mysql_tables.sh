# This is typically called from the `create_aws_infrastructure.py` script.
# The first argument is the public IPv4 address of the manager node VM.
# The second argument is the path to the key file.
ssh -i $2 -o "StrictHostKeyChecking no" ubuntu@$1 <<'ENDSSH'
cd /home/ubuntu/mysql_scripts
mysql --host=localhost --port=22 -u user -p123password123 vanilla_hopsfs < schema.sql &&
mysql --host=localhost --port=22 -u user -p123password123 vanilla_hopsfs < update-schema_2.8.2.1_to_2.8.2.2.sql &&
mysql --host=localhost --port=22 -u user -p123password123 vanilla_hopsfs < update-schema_2.8.2.2_to_2.8.2.3.sql &&
mysql --host=localhost --port=22 -u user -p123password123 vanilla_hopsfs < update-schema_2.8.2.3_to_2.8.2.4.sql &&
mysql --host=localhost --port=22 -u user -p123password123 vanilla_hopsfs < update-schema_2.8.2.4_to_2.8.2.5.sql &&
mysql --host=localhost --port=22 -u user -p123password123 vanilla_hopsfs < update-schema_2.8.2.5_to_2.8.2.6.sql &&
mysql --host=localhost --port=22 -u user -p123password123 vanilla_hopsfs < update-schema_2.8.2.6_to_2.8.2.7.sql &&
mysql --host=localhost --port=22 -u user -p123password123 vanilla_hopsfs < update-schema_2.8.2.7_to_2.8.2.8.sql &&
mysql --host=localhost --port=22 -u user -p123password123 vanilla_hopsfs < update-schema_2.8.2.8_to_2.8.2.9.sql &&
mysql --host=localhost --port=22 -u user -p123password123 vanilla_hopsfs < update-schema_2.8.2.9_to_2.8.2.10.sql &&
mysql --host=localhost --port=22 -u user -p123password123 vanilla_hopsfs < update-schema_2.8.2.10_to_3.2.0.0.sql &&
mysql --host=localhost --port=22 -u user -p123password123 vanilla_hopsfs < serverless.sql
ENDSSH