"""
""
"""
import base64
import json
import subprocess
import urllib

import requests
from bs4 import BeautifulSoup

from configuration.ecs_saml_demo_configuration import ECSSAMLConfiguration
from logger import ecs_logger
import errno
import getpass
import os
import traceback
import signal
import time
import logging
import re
import xml.etree.ElementTree as ET
import boto3

# Constants
MODULE_NAME = "ECS_SAML_DEMO_Module"  # Module Name
INTERVAL = 30  # In seconds
CONFIG_FILE = 'ecs_saml_demo_config.json'  # Default Configuration File

# Globals
_configuration = None
_logger = None
_stsAccessKeyId = None
_stsSecretKey = None
_stsSessionToken = None
_awsCli = list()


class AWSDataCollection:
    def __init__(self, method, logger, sts_endpoint, tempdir, saml_assertion_input, index_role_to_assume_input, token_session_duration, namespace_endpoint):
        self.method = method
        self.logger = logger
        self.tempdir = tempdir
        self.sts_endpoint = sts_endpoint
        self.assertion = saml_assertion_input
        self.index_role_to_assume = index_role_to_assume_input
        self.token_duration = token_session_duration
        self.namespace_endpoint = namespace_endpoint

        logger.info(MODULE_NAME + '::AWSDataCollection()::init method of class called')

        try:
            self.logger.info(MODULE_NAME + '::AWSDataCollection()::Starting method: ' + self.method)

            if self.method == 'aws_assume_role_saml':
                # Make AWS CLI Call to assume role with SAML
                aws_assume_role_saml(self.logger, self.sts_endpoint, self.tempdir, self.assertion, self.index_role_to_assume, self.token_duration)
            else:
                self.logger.info(MODULE_NAME + '::AWSDataCollection()::Requested method ' +
                                 self.method + ' is not supported.')
        except Exception as e:
            _logger.error(MODULE_NAME + 'AWSDataCollection::run()::The following unexpected '
                                        'exception occured: ' + str(e) + "\n" + traceback.format_exc())


class ECSSAMLAssertion:
    def __init__(self, assertion):
        self.saml_assertion = assertion
        self.roles = []
        self.providers = []
        self.shortRoles = []

    def addRole(self, role):
        self.roles.append(role)

    def addShortRole(self, role):
        self.shortRoles.append(role)

    def addProvider(self, provider):
        self.roles.providers(provider)


def ecs_config(config, temp_dir):
    global _configuration
    global _logger

    try:
        # Load and validate module configuration
        _configuration = ECSSAMLConfiguration(config, temp_dir)

        # Grab loggers and log status
        _logger = ecs_logger.get_logger(__name__, _configuration.logging_level)
        _logger.info(MODULE_NAME + '::ecs_config()::We have configured logging level to: '
                     + logging.getLevelName(_configuration.logging_level))
        _logger.info(MODULE_NAME + '::ecs_config()::Configuring ECS SAML Demo Module complete.')
        return _logger
    except Exception as e:
        _logger.error(MODULE_NAME + '::ecs_config()::The following unexpected '
                                    'exception occured: ' + str(e) + "\n" + traceback.format_exc())


def aws_assume_role_saml(logger, sts_endpoint, tempdir, assertion, index_of_role_to_assume, token_duration):
    # Function removed as it is not used
    pass


def aws_generate_temp_credentials_profile():
    # Function removed as it is not used
    pass


def file_write(filename, content):
    # Open the file in write mode, which will overwrite any previous content
    with open(filename, "w", encoding="utf-8") as f:
        # Write the content to the file
        f.write(content)


def ecs_ido_sso_login(username, password):
    global _logger
    global _configuration

    # Initiate session handler
    session = requests.Session()

    # Programmatically get the SAML assertion
    # Opens the initial IdP url and follows all of the HTTP302 redirects, and
    # gets the resulting login page
    sslverification = False
    formresponse = session.get(_configuration.saml_idp_url, verify=sslverification)

    # Debug the response code if needed
    #print(formresponse.status_code)

    # Return logic - Seen the need for this in some Ping Federate environments
    while formresponse.status_code == 401:
        formresponse = session.get(formresponse.url)

    # Capture the idpauthformsubmiturl, which is the final url after all the 302s
    idpauthformsubmiturl = formresponse.url

    # Parse the response and extract all the necessary values
    # in order to build a dictionary of all of the form values the IdP expects
    formsoup = BeautifulSoup(formresponse.text, features="lxml")
    payload = {}

    for inputtag in formsoup.find_all(re.compile('(INPUT|input)')):
        name = inputtag.get('name', '')
        value = inputtag.get('value', '')
        if "user" in name.lower():
            # Make an educated guess that this is the right field for the username
            payload[name] = username
        elif "email" in name.lower():
            # Some IdPs also label the username field as 'email'
            payload[name] = username
        elif "pass" in name.lower():
            # Make an educated guess that this is the right field for the password
            payload[name] = base64.b64decode(password).decode()
        else:
            # Simply populate the parameter with the existing value (picks up hidden fields in the login form)
            payload[name] = value

    # Quick fix when AuthMethod is beeing wiped by another hidden input field in login page, and it turned out this one is really important.
    payload["AuthMethod"] = "FormsAuthentication"

    # Debug the parameter payload if needed
    # Use with caution since this will print sensitive output to the screen
    # print payload

    # Some IdPs don't explicitly set a form action, but if one is set we should
    # build the idpauthformsubmiturl by combining the scheme and hostname
    # from the entry url with the form action target
    # If the action tag doesn't exist, we just stick with the
    # idpauthformsubmiturl above
    for inputtag in formsoup.find_all(re.compile('(FORM|form)')):
        action = inputtag.get('action')
        loginid = inputtag.get('id')
        if action and loginid == "loginForm":
            parsedurl = urllib.parse.urlparse(_configuration.saml_idp_url)
            idpauthformsubmiturl = parsedurl.scheme + "://" + parsedurl.netloc + action

    # Performs the submission of the IdP login form with the above post data
    response = session.post(
        idpauthformsubmiturl, data=payload, verify=sslverification)

    # Debug the response if needed
    #print(response.text)
    file_write("output.html", response.text)    

    # Overwrite and delete the credential variables, just for safety
    username = '##############################################'
    password = '##############################################'
    del username
    del password

    # Decode the response and extract the SAML assertion
    soup = BeautifulSoup(response.text, features="lxml")
    assertion = ''
    urlEncodedAssertion = ''

    # Look for the SAMLResponse attribute of the input tag (determined by
    # analyzing the debug print lines above)
    for inputtag in soup.find_all('input'):
        if (inputtag.get('name') == 'SAMLResponse'):
            # print(inputtag.get('value'))
            assertion = inputtag.get('value')

    # Better error handling is required for production use.
    if assertion == '':
        _logger.error(MODULE_NAME + '::ecs_ido_sso_login()::The Identity Provider '
                                    'did not return a valid SAML Assertion.')
        return None

    # Debug only
    print("#################### BASE64 SAML Assertion ###############################:")
    print(assertion)
    # print(base64.b64decode(assertion))
    print("#################################################################:")

    print("#################### URL ENCODED Saml Assertion for ECS STS API Call ###############################:")
    urlEncodedAssertion = urllib.parse.quote_plus(assertion)
    print(urlEncodedAssertion)
    print("#################################################################:")

    # Create our ECSSAMLAssertion class instance
    ecsAssertion = ECSSAMLAssertion(assertion)

    # Parse the returned assertion and extract the authorized roles
    awsRoles = []
    root = ET.fromstring(base64.b64decode(assertion))
    for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
        if saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role':
            for saml2AttributeValue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                awsRoles.append(saml2AttributeValue.text)

    # Note the format of the attribute value should be role_arn,principal_arn
    # but lots of blogs list it as principal_arn,role_arn so let's reverse
    # them if needed
    for awsRole in awsRoles:
        chunks = awsRole.split(',')
        if 'saml-provider' in chunks[0]:
            newAwsRole = chunks[1] + ',' + chunks[0]
            index = awsRoles.index(awsRole)
            awsRoles.insert(index, newAwsRole)
            awsRoles.remove(awsRole)

    # If I have more than one role, ask the user which one they want,
    # otherwise just proceed
    print("")
    i = 0
    print("The following provider/role combinations are contained in the provided SAML Assertion "
          "and can be used with the with teh ECS AssumeRoleWithSAML STS api call")
    _samlAssertionRoles = {}
    for awsRole in awsRoles:
        stringFullRoleArn = awsRole.split(',')[0]
        ecsAssertion.roles.append(stringFullRoleArn)
        stringShortRole = stringFullRoleArn.split('/')[1]
        ecsAssertion.shortRoles.append(stringShortRole)
        ecsAssertion.providers.append(awsRole.split(',')[1])
        print('[', i, ']: ', awsRole.split(',')[0], awsRole.split(',')[1])
        i += 1
    return ecsAssertion


def assume_role_with_saml_boto3(logger, sts_endpoint, assertion, index_of_role_to_assume, token_duration):
    global _stsAccessKeyId
    global _stsSecretKey
    global _stsSessionToken

    try:
        client = boto3.client('sts', endpoint_url=sts_endpoint, verify=False)
        response = client.assume_role_with_saml(
            RoleArn=assertion.roles[index_of_role_to_assume],
            PrincipalArn=assertion.providers[index_of_role_to_assume],
            SAMLAssertion=assertion.saml_assertion,
            DurationSeconds=int(token_duration)
        )

        credentials = response['Credentials']
        _stsAccessKeyId = credentials['AccessKeyId']
        _stsSecretKey = credentials['SecretAccessKey']
        _stsSessionToken = credentials['SessionToken']

        logger.info(MODULE_NAME + '::assume_role_with_saml_boto3()::Retrieved temporary credentials.')
        logger.info(MODULE_NAME + '::assume_role_with_saml_boto3()::aws_access_key_id: ' + _stsAccessKeyId)
        logger.info(MODULE_NAME + '::assume_role_with_saml_boto3()::aws_secret_access_key: ' + _stsSecretKey)
        logger.info(MODULE_NAME + '::assume_role_with_saml_boto3()::aws_session_token: ' + _stsSessionToken)

        return True
    except Exception as e:
        logger.error(MODULE_NAME + '::assume_role_with_saml_boto3()::The following unexpected exception occurred: ' + str(e) + "\n" + traceback.format_exc())
        return False

def list_s3_buckets(logger, namespace_endpoint, prefix='  '):
    global _stsAccessKeyId
    global _stsSecretKey
    global _stsSessionToken

    # Ensure credentials are set
    if not _stsAccessKeyId or not _stsSecretKey or not _stsSessionToken:
        logger.info(MODULE_NAME + '::list_s3_buckets()::Temporary credentials are not set. Cannot list S3 buckets.')

        return False

    session = boto3.Session(
        aws_access_key_id=_stsAccessKeyId,
        aws_secret_access_key=_stsSecretKey,
        aws_session_token=_stsSessionToken
    )

    s3 = session.client('s3', endpoint_url=namespace_endpoint, verify=False)
    response = s3.list_buckets()

    for bucket in response['Buckets']:
        print(f'{prefix}{bucket["Name"]}')

    return True

"""
Main 
"""
if __name__ == "__main__":

    try:
        # Dump out application path
        currentApplicationDirectory = os.getcwd()
        configFilePath = os.path.abspath(os.path.join(currentApplicationDirectory, "configuration", CONFIG_FILE))
        tempFilePath = os.path.abspath(os.path.join(currentApplicationDirectory, "temp"))

        # Create temp directory if it doesn't already exists
        if not os.path.isdir(tempFilePath):
            os.mkdir(tempFilePath)
        else:
            # The directory exists so lets scrub any temp XML files out that may be in there
            files = os.listdir(tempFilePath)
            for file in files:
                if file.endswith(".xml"):
                    os.remove(os.path.join(currentApplicationDirectory, "temp", file))

        print(MODULE_NAME + "::__main__::Current directory is : " + currentApplicationDirectory)
        print(MODULE_NAME + "::__main__::Configuration file path is: " + configFilePath)

        # Initialize configuration and VDC Lookup
        log_it = ecs_config(configFilePath, tempFilePath)

        # 1. Prompt for AD credentials
        # 2. Perform and SSO Login to our configured IdP
        # 3. Process returned HTML form to set the user and password and submit the form
        # to retrieve a SAML assertion
        # 4. URL Encode the SAML Assertion
        # 5. Call the ECS STS API to perform an AssumeRoleWithSAML Call to get a temporary set of credentials

        # Gather credentials and IDP URL
        print("Enter Active Directory User:")
        username = input()
        password = base64.b64encode(getpass.getpass().encode())
        print('')

        # Perform the SSO login to the IDP and process the assertion
        saml_assertion = ecs_ido_sso_login(username, password)

        # If we have a valid assertion make a call the ECS STS API using the
        # first role / provider combination in the assertion object
        if not (saml_assertion is None):
            # First lets have the user select the role from the assertion they want to assume role with
            while True:
                print("Please enter the name of one of the following roles contained in the assertion that you "
                      "want to assume:\r\n\t\t")
                roleToAssume = input(saml_assertion.shortRoles)

                bRoleExists = False
                index_of_role_to_assume = 0
                for r in saml_assertion.shortRoles:
                    if r == roleToAssume:
                        bRoleExists = True
                        break
                    else:
                        index_of_role_to_assume += 1

                if not bRoleExists:
                    print("The role entered does not exist in the SAML Assertion.\r\n")
                    continue
                else:
                    if assume_role_with_saml_boto3(log_it, _configuration.aws_sts_endpoint, saml_assertion, index_of_role_to_assume, _configuration.aws_token_session_duration):
                        print(f"Test the temporary credentials as {roleToAssume}, by listing the S3 buckets.")
                        list_s3_buckets(log_it, _configuration.aws_namespace_endpoint)
                    else:   
                        print("Failed to assume role and retrieve temporary credentials.\r\n")
                        break

    except Exception as e:
        print(MODULE_NAME + '__main__::The following unexpected error occurred: '
              + str(e) + "\n" + traceback.format_exc())