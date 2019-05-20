import configparser
import os
import getpass
import requests
from requests.auth import HTTPBasicAuth

auphonic_oauth_url = 'https://auphonic.com/oauth2/token/'

config = configparser.RawConfigParser()

config.read([os.path.join(os.environ.get('AST_CONFIG_DIR', '/etc/asterisk'), 'audio-postpro.cfg'),
             os.path.expanduser('~/.audio-postpro.cfg'),
             os.environ.get('FAX2MAIL_CONFIG', 'audio-postpro.cfg')],
            encoding='utf-8')

auphonic_clientid = config.get('auphonic', 'clientid', fallback=None)
auphonic_clientsecret = config.get('auphonic', 'clientsecret', fallback=None)

if auphonic_clientid is None or auphonic_clientsecret is None:
    raise Exception('unable to load auphonic OAuth2 client secrets from config')

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
