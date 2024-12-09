# ecs-saml-with-boto3-cli
Demo application that will perform an SSO login and then use the boto3 module to perform the AssumeRoleWith SAML, as well as listing buckets using the credentials given.

This app was tested with the following installed:
- Python 3.11.8
  - Requires the following Python modules to be installed:
    - requests
    - bs4
    - lxml
- boto3 CLI 2.1.17
