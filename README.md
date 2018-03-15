# Security Checks for Google Cloud Platform #

| Security Check | Logging Capability | Removal Capability | Additional Notes |
|-----------------------------------|--------------------|--------------------|------------------|
| World-readable Bucket Permissions | Completed | Completed | [\*Bug Fixed\*](https://github.com/GoogleCloudPlatform/google-cloud-python/issues/4682) Checks for buckets with AllUsers or AllAuthenticatedUsers groups |
| Legacy Bucket Permissions | Completed | Completed | Checks for buckets with legacyBucketReader and legacyBucketOwner permissions |
| Default Service Accounts | Completed | Completed | TODO: Add Deletion of Service Accounts from IAM and replace len() with try/except |
| Default VPC | Completed | N/A | Checks for VPC named "default" that has Automatic Subnet Mode enabled |
| Non-US Subnets in VPC | Completed | N/A | Checks for any Subnets not in the U.S. |
| Service Account Keys Rotation | Completed | N/A | Checks for Keys older than 180 days |
| Non-Organizational User Accounts | Completed | N/A | Checks for non-Organizational accounts in IAM |
| Non-Organizational Bucket Users | Completed | N/A | Checks for non-Organizational accounts on Buckets |
| Cloud SQL not Enforced | Completed | N/A | Checks for Cloud SQL Instances that don't have SSL Encryption required |
| Cloud SQL Authorized Networks Allowed | TBD | N/A | Checks for Cloud SQL Instances that have IPs Whitelisted |
| Cloud SQL User Accounts | TBD | | |
| Data Access Logs Enabled | TBD | N/A | Checks that [Data Access](https://cloud.google.com/logging/docs/audit/configure-data-access) Logs are enabled |

**How to install Python 3 and use the script(s):**

- Install Python 3, virtualenv, pip and requirements (see install_python.sh)
- Create Virtualenv and install requirements (run the commands below)
    - cd ~
    - virtualenv venv --python=python3
    - source venv/bin/activate
    - pip3 install -r google-python-security/requirements.txt
- Within your Google Cloud Project, create a Service Account with No Role and download JSON Key
- Associate the GCP Service Account at the Organizational Level and give the following custom permissions:
    - cloudsql.databases.get
    - cloudsql.databases.list
    - cloudsql.instances.get
    - cloudsql.instances.list
    - cloudsql.sslCerts.get
    - cloudsql.sslCerts.list
    - compute.networks.get
    - compute.networks.list
    - iam.serviceAccountKeys.get
    - iam.serviceAccountKeys.list
    - iam.serviceAccounts.get
    - iam.serviceAccounts.list
    - storage.buckets.get
    - storage.buckets.getIamPolicy
    - storage.buckets.list
    - storage.objects.get
    - storage.objects.getIamPolicy
    - storage.objects.list
    - resourcemanager.projects.get
    - resourcemanager.projects.getIamPolicy
    - resourcemanager.projects.list
    - storage.buckets.setIamPolicy (only needed for removal functionality)
    - storage.objects.setIamPolicy (only needed for removal functionality)
- Create the directory: ~/.gcp
- Move Service Account Key and rename file to: ~/.gcp/cloudsecurity-monitoring.json
- Clone Repo
- Modify credentials_template.py, add requested information and rename to credentials.py- Modify gcp.py and add Service Account Key name to get_function()
