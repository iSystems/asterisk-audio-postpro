import re
import requests


class AuphonicProduction:

    _uuid = None
    _data = None

    def __init__(self, accesstoken, uuid=None):
        self._accesstoken = accesstoken
        if uuid is not None:
            self.uuid = uuid

    def _get_uuid(self):
        if self._uuid is None:
            self._uuid = self.new()
        return self._uuid

    def _set_uuid(self, uuid):
        if type(uuid) is not str:
            raise TypeError('uuid must be a string')
        if not re.match('^\w{22,}$', uuid):
            raise ValueError('Invalid uuid format')
        if self._uuid is not None:
            raise AttributeError('procudtion uuid allready set')
        self._uuid = uuid

    uuid = property(_get_uuid, _set_uuid)

    def _apicall(self, url, data=None, json=None, files=None, method='POST'):
        if not (method.upper() == 'POST' or method.upper() == 'GET'):
            raise ValueError('method may only be POST or GET')
        headers = {'Authorization': "Bearer %s" % self._accesstoken}
        r = requests.request(method.upper(), url, headers=headers, json=json, data=data, files=files)
        if r.status_code == 200:
            return r.json()
        raise RuntimeError('failed to make auphonic api request, statuscode: %s, response: %s' % (r.status_code, r.text) )

    def upload(self, file_or_fp):
        if type(file_or_fp) is str:
            file_or_fp = open(file_or_fp, 'rb')
        return self._apicall('https://auphonic.com/api/production/%s/upload.json' % self.uuid, files={'input_file': file_or_fp})

    def start(self):
        return self._apicall('https://auphonic.com/api/production/%s/start.json' % self.uuid)

    def change(self, data):
        if type(data) is not dict:
            raise TypeError
        return self._apicall('https://auphonic.com/api/production/%s.json' % self.uuid, json=data)

    def update(self):
        resp = self._apicall("https://auphonic.com/api/production/%s.json" % self.uuid, method='GET')
        self._data = resp['data']

    def __getitem__(self, item):
        if self._data is not None and item in self._data:
            return self._data[item]
        raise KeyError

    @classmethod
    def new(cls, accesstoken, preset = None, metadata = None, webhook = None):

        json = {}
        if preset is not None:
            if type(preset) is not str:
                raise TypeError('preset must be a str')
            if not re.match('^\w{22,}$', preset):
                raise ValueError('Invalid preset uuid format')
            json['preset'] = preset
        if metadata is not None:
            if type(metadata) is not dict:
                raise TypeError('metadata must be a dictionary')
        if webhook is not None:
            if type(webhook) is not str:
                raise TypeError('webhook must be a str')
            json['webhook'] = webhook
        production = cls(accesstoken)
        resp = production._apicall("https://auphonic.com/api/productions.json", json=json)
        production.uuid = resp['data']['uuid']
        return production

    @classmethod
    def fetch(cls, accesstoken, uuid):
        production = cls(accesstoken, uuid)
        production.update()
        return production