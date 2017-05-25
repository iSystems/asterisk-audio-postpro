import asyncio
import configparser
import hashlib
import json
import re
import shlex
import tempfile
from pprint import pprint
from urllib import parse

import requests
import os.path
import logging
import subprocess

# based on c3nav-commitid-suggest by nomoketo
from Auphonic import AuphonicProduction

config = configparser.RawConfigParser()

config.read([os.path.join(os.environ.get('AST_CONFIG_DIR', '/etc/asterisk'), 'audio-postpro.cfg'),
             os.path.expanduser('~/.audio-postpro.cfg'),
             os.environ.get('FAX2MAIL_CONFIG', 'audio-postpro.cfg')],
            encoding='utf-8')

auphonic_accesstoken = config.get('auphonic', 'accesstoken')

numeric_level = getattr(logging, config.get('server', 'loglevel').upper(), None)
if not isinstance(numeric_level, int):
    raise ValueError('Invalid log level: %s' % config.get('server', 'loglevel'))
logging.basicConfig(level=numeric_level, filename=config.get('server', 'logfile', fallback=None))


if not os.path.isdir(config.get('paths', 'spooldir')):
    raise Exception('spooldir (%s) not found' % config.get('paths', 'spooldir'))

spooldir = {}
for folder in ['tmp', 'state', 'original', 'processed']:
    spooldir[folder] = os.path.abspath(config.get('paths', folder,
                                                  fallback=os.path.join(config.get('paths', 'spooldir'), folder)))
    os.makedirs(spooldir[folder], exist_ok=True)

class WebhookServerProtocol(asyncio.Protocol):
    max_request_size = 10000
    max_payload_size = 100000

    def connection_made(self, transport):
        self.transport = transport
        self.debug = []
        self.in_payload = False
        self.handled = False
        self.method = None
        self.path = None
        self.qs = None
        self.protocol = 'HTTP/1.1'
        self.request = b''
        self.payload = b''
        self.done = False
        self.headers = {}

    def data_received(self, data):
        try:
            if not self.in_payload:
                if len(data) > self.max_request_size + self.max_payload_size:
                    return self.response(413, 'Request Entity Too Large')
                self.request += data
                if b'\r\n\r\n' in self.request:
                    self.request, self.payload = self.request.split(b'\r\n\r\n', 1)
                    self.in_payload = True
                    self.parse_request()
                    if self.done:
                        return
                if len(self.request) > self.max_request_size:
                    return self.response(431, 'Request Entity Too Large')
            else:
                self.payload += data
            if self.in_payload and len(self.payload) >= self.headers.get('Content-Length', 0):
                self.handle_request()
        except:
            self.response(500, 'Internal Server Error')
            raise

    def eof_received(self):
        try:
            self.handle_request()
        except:
            self.response(500, 'Internal Server Error')
            raise

    def response(self, status_code=200, status_name='OK', message=''):
        self.done = True
        print(status_code, status_name, '-', ' '.join(self.debug), '-', message)
        if type(message) != bytes:
            message = message.encode()
        self.transport.write(('%s %d %s\r\n' % (self.protocol, status_code, status_name)).encode())
        self.transport.write(b'Server: isystems-paps-taskrunner\r\n')
        self.transport.write(('Content-Length: %d\r\n' % len(message)).encode())
        self.transport.write(b'Connection: close\r\n')
        self.transport.write(b'Content-Type: text/plain\r\n')
        self.transport.write(b'\r\n')
        self.transport.write(message)
        self.transport.close()

    def parse_request(self):
        lines = self.request.decode().split('\n')
        first_line = lines.pop(0).rstrip().split(' ')
        if len(first_line) != 3:
            return self.response(400, 'Bad Request')
        self.method, self.path, self.protocol = first_line
        if '?' in self.path:
            self.path, self.qs = self.path.split('?', 1)
        if self.protocol not in ('HTTP/1.1', 'HTTP/1.0'):
            return self.response(400, 'Bad Request')
        for line in lines:
            name, value = line.split(':', 1)
            name = name.title()
            value = value.strip()
            if ' ' in name:
                return self.response(400, 'Bad Request')
            if name.title() == 'Content-Length':
                value = int(value)
                if value > self.max_payload_size:
                    return self.response(413, 'Request Entity Too Large')
            self.headers[name] = value
        self.in_payload = True

    def handle_request(self):
        if not self.in_payload:
            self.parse_request()
            if self.done:
                return
        if self.handled:
            return
        self.handled = True
        if self.headers.get('Content-Type') == 'application/x-www-form-urlencoded':
            self.data=parse.parse_qs(self.payload.decode())
        if self.method != 'POST':
            return self.response(405, 'Method Not Allowed', message='This is an API server.')
        elif self.path == '/auphonic/webhook':
            return self.handle_auphonic_webhook()
        else:
            return self.response(404, 'Not Found', message='This is an API server.')
            #return self.response(401, 'Unauthorized', message='This is an API server.')
        return self.response(500, 'Internal Server Error', message='I don\'t know what to say...')

    def md5sum(self, fname):
        md5hash = hashlib.md5()
        with open(fname, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                md5hash.update(chunk)
        return md5hash.hexdigest()

    def auphonic_get_production(self, production_uuid):
        headers = {'Authorization': "Bearer %s" % auphonic_accesstoken}
        r = requests.get("https://auphonic.com/api/production/%s.json" % production_uuid, headers=headers)
        if r.status_code == 200:
            return r.json()
        self.debug.append("Failed to get auphonic production details, (response code %s)" % r.status_code)

    def auphonic_donwload(self, url, file_or_fp):
        headers = {'Authorization': "Bearer %s" % auphonic_accesstoken}
        r = requests.get(url, headers=headers, stream=True)
        if r.status_code == 200:
            if type(file_or_fp) is str:
                file_or_fp = open(file_or_fp, 'rb')
            for chunk in r.iter_content(chunk_size=1024):
                if chunk: #filter out keep-allive new chunks
                    file_or_fp.write(chunk)
            file_or_fp.close()
            return file_or_fp.name
        raise RuntimeError('failed to download %s, statuscode: %s' % (url, r.status_code))

    def handle_auphonic_webhook(self):
        if not ('status' in self.data and 'uuid' in self.data):
            return self.response(400, 'Bad Request', message='Not enough parameters.')
        self.auphonic_uuid = self.data['uuid'][0]
        self.auphonic_status = int(self.data['status'][0])

        self.debug.append('auphonic webhook, uuid=%s, status=%s' % (self.auphonic_uuid, self.auphonic_status))

        if not re.match('^\w{22,}$', self.auphonic_uuid):
            return self.response(400, 'Bad Request', message='Invalid uuid format.')
        elif self.auphonic_status == 2:
            # error status
            # TODO: email support
            return self.response(200, 'OK', message='Thanks, informing support.')
        elif self.auphonic_status != 3:
            return self.response(202, 'Accepted', message='Thanks for the info.')

        try:
            with open(os.path.join(spooldir['state'], "%s.json" % self.auphonic_uuid)) as fp:
                self.production = json.load(fp)
        except FileNotFoundError:
            return self.response(404, 'Not Found', message='Production UUID not found')
        except json.JSONDecodeError as err:
            self.debug.append('Failed to decode json, %s' % err)
            return self.response(500, 'Internal Server Error', message='error loading production')

        try:
            self.auphonic = AuphonicProduction.fetch(auphonic_accesstoken, self.auphonic_uuid)
        except RuntimeError as err:
            self.debug.append('Failed to load auphonic production, %s' % err)
            return self.response(500, 'Internal Server Error', message='error loading production')

        if not ('uuid' in self.production and 'inputfile'in self.production):
            logging.error('%s.json is missing needed values' % self.auphonic_uuid)
            return self.response(500, 'Internal Server Error', message='error loading production')

        if self.production.get('uuid', '') !=  self.auphonic_uuid:
            logging.error('%s.json uuid missmatch' % self.auphonic_uuid)
            return self.response(500, 'Internal Server Error', message='error loading production')

        os.makedirs(os.path.join(spooldir['processed'], self.auphonic_uuid), exist_ok=True)
        os.makedirs(os.path.join(spooldir['tmp'], self.auphonic_uuid), exist_ok=True)

        outputfiles = []
        try:
            for outputfile in self.auphonic['output_files']:
                print('Output file download url for production %s: %s' % (self.auphonic_uuid, outputfile['download_url']))
                sane_filename = os.path.basename(outputfile['filename'])
                outputfilepath = os.path.join(spooldir['processed'], self.auphonic_uuid, sane_filename)

                if os.path.isfile(outputfilepath):
                    if outputfile['checksum'] == self.md5sum(outputfilepath):
                        logging.debug('skipped %s, localfile is identical to remote file' % sane_filename)
                        outputfiles.append(outputfilepath)
                        continue
                    logging.debug('redownloading %s, local file doesn\'t match remote file' % sane_filename)
                    os.remove(outputfilepath)

                tmp = tempfile.NamedTemporaryFile(dir=spooldir['tmp'], delete=False)
                try:
                    self.auphonic_donwload(outputfile['download_url'], tmp)
                    os.replace(tmp.name, outputfilepath)
                except RuntimeError as err:
                    logging.exception('error downloading output files of production %s: %s' % (self.auphonic_uuid, err))
                    return self.response(500, 'Internal Server Error', message='error downloading production')
                except OSError as err:
                    logging.exception('failed to move %s -> $s: %s' % (tmp.name, outputfilepath, err))
                    return self.response(500, 'Internal Server Error', message='error downloading production')
                outputfiles.append(outputfilepath)
        except KeyError:
            pprint(self.auphonic)
            return self.response(500, 'Internal Server Error', message='error downloading production')

        auphonicfile = None
        if len(outputfiles) == 0:
            return self.response(500, 'Internal Server Error', message='error processing production, no output files')
        for outputfile in outputfiles:
            if outputfile.endswith('.flac'):
                auphonicfile = outputfile

        if auphonicfile is None:
            return self.response(500, 'Internal Server Error',
                                 message='error processing production, no suitable output files')

        originalpath, originalformat = self.production['inputfile'].rsplit('.', maxsplit=1)
        originalreplaced = False
        soxoutputfiles = []
        for fileformat in config.get('output', 'fileformats', fallback='sln16').split(' '):
            soxoutputargs = config.get('sox', 'fileformat_%s' % fileformat, fallback=None)
            if soxoutputargs is None:
                self.debug.append('WARNING: unknown outputformat %s' % fileformat)
                continue
            soxoutputfile = '%s.%s' % (os.path.basename(auphonicfile).rsplit('.', maxsplit=1)[0], fileformat)
            soxoutputfile = os.path.join(spooldir['tmp'], self.auphonic_uuid, soxoutputfile)
            logging.debug('sox outputfile: %s' % soxoutputfile)
            soxargs = [config.get('sox', 'sox', fallback='sox'), '-t', 'flac', auphonicfile]
            soxargs += shlex.split(soxoutputargs)
            soxargs.append(soxoutputfile)
            logging.debug('running %s' % ' '.join(soxargs))
            try:
                sox = subprocess.run(soxargs, check=True)
            except subprocess.CalledProcessError as e:
                logging.exception('Failed to run sox, cmdline: %s, stderr: %s, stdout:%s' %
                                  (e.cmd, (e.stderr if not None else ''), (e.output if not None else '')))
                return self.response(500, 'Internal Server Error', message='error processing production')

            soxoutputfiles.append(soxoutputfile)
            try:
                os.replace(soxoutputfile, '%s.%s' % (originalpath, fileformat))
                logging.debug('moving/replacing %s -> %s.%s' (soxoutputfile, originalpath, fileformat))
            except OSError as err:
                logging.error('Failed to move processed file to original file location')
                return self.response(500, 'Internal Server Error', message='error processing production')
            if fileformat == originalformat:
                originalreplaced = True

        if len(soxoutputfiles) == 0:
            logging.error('Server misconfiguration, no suitable fileformats configured')
            return self.response(500, 'Internal Server Error', message='error processing production')

        if not originalreplaced:
            logging.warning('No output fileformat configured matching the original file, original file NOT replaced')

        return self.response(200, 'OK', message='Postprocessing Finished')



loop = asyncio.get_event_loop()
coro = loop.create_server(WebhookServerProtocol, config.get('server', 'listen_address', fallback='127.0.0.1'),
                          config.get('server', 'listen_port', fallback=8080))
server = loop.run_until_complete(coro)
print('Serving on {}'.format(server.sockets[0].getsockname()))
try:
    loop.run_forever()
except KeyboardInterrupt:
    pass
server.close()
loop.run_until_complete(server.wait_closed())
loop.close()