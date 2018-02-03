- Install Python 3, virtualenv, pip and requirements (see install.sh)

- Within your Google Cloud Project, create a Service Account with No Role and download JSON Key

- Associate the GCP Service Account at the Organizational Level and give Storage Admin Permissions

- Create the directory: ~/.gcp

- Move Service Account Key and rename file to: ~/.gcp/[key file].json

- Clone Repo

- Modify gcp.py and add Service Account Key name to get_function()
