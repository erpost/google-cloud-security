# Security Checks for Google Cloud Platform #

| Security Check | Logging Capability | Removal Capability | Additional Notes |
|-----------------------------------|--------------------|--------------------|------------------|
| World-readable Bucket Permissions | Completed | Completed | [Bug Fixed](https://github.com/GoogleCloudPlatform/google-cloud-python/issues/4682) |
| Legacy Bucket Permissions | Completed | Completed | |
| Default Service Accounts | Completed | In Progress | TODO: Delete Service Accounts from IAM |
| Default VPC | Completed | N/A | "default" VPC name is not reserved |
| Service Account Keys Rotation | Completed | N/A | Checks for Keys older than 180 days |
| Non-Organizational User Accounts | Completed | N/A | Checks for non-Organizational accounts in IAM |
| Non-Organizational Bucket Users | In Progess | | Checks for non-Organizational accounts on Buckets |


- Install Python 3, virtualenv, pip and requirements (see install.sh)
- Create Virtualenv and install requirements (run the commands below)
    - cd ~
    - virtualenv venv --python=python3.4
    - source venv/bin/activate
    - pip3 install -r google-python-security/requirements.txt
- Within your Google Cloud Project, create a Service Account with No Role and download JSON Key
- Associate the GCP Service Account at the Organizational Level and give the following custom permissions:
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
    - storage.buckets.setIamPolicy (only needed for removal functionality)
    - storage.objects.setIamPolicy (only needed for removal functionality)
- Create the directory: ~/.gcp
- Move Service Account Key and rename file to: ~/.gcp/[key file].json
- Clone Repo
- Modify gcp.py and add Service Account Key name to get_function()
