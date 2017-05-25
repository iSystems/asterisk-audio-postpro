import json
import getpass
import requests
from requests.auth import HTTPBasicAuth

auphonic_oauth_url = 'https://auphonic.com/oauth2/token/'

try:
    config = json.load(open('config.json'))
    auphonic_clientid = config['auphonic']['clientid']
    auphonic_clientsecret = config['auphonic']['clientsecret']
except KeyError as err:
    raise Exception('unable to load auphonic OAuth2 client secrets from config')
except json.JSONDecodeError as err:
    raise Exception('could not parse config file')
except FileNotFoundError as err:
    raise Exception('config file not found')

auphonic_username = input('Auphonic Username:')
auphonic_password = getpass.getpass('Auphonic Password:')

print("Getting OAuth2 Access Token for user %s " % auphonic_username)
data = {
         'client_id': auphonic_clientid,
         'username': auphonic_username,
         'password': auphonic_password,
         'grant_type': 'password'
}

tokenresponse = requests.post(auphonic_oauth_url, data, auth=HTTPBasicAuth(auphonic_clientid, auphonic_clientsecret))

if tokenresponse.status_code != 200:
    raise Exception('Failed to get auphonic access token, http status: %s' % tokenresponse.status_code)

auphonic_accesstoken = tokenresponse.json()['access_token']
auphonic_accesstoken_expires = tokenresponse.json()['expires_in']
print("Got access token %s for user %s" % (auphonic_accesstoken, auphonic_username))
