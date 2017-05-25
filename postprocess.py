import asyncio
import configparser
import json
import re
import shlex
import shutil
import subprocess
import tempfile
from pprint import pprint
from urllib import parse

import requests
import os.path
import sys
import logging

from Auphonic import AuphonicProduction

if len(sys.argv) <= 1:
    print ('usage: %s [inputfile] [inputfile] ...')

config = configparser.RawConfigParser()
config.read([os.path.join(os.environ.get('AST_CONFIG_DIR', '/etc/asterisk'), 'audio-postpro.cfg'),
             os.path.expanduser('~/.audio-postpro.cfg'),
             os.environ.get('FAX2MAIL_CONFIG', 'audio-postpro.cfg')],
            encoding='utf-8')

auphonic_accesstoken = config.get('auphonic', 'accesstoken')

numeric_level = getattr(logging, config.get('process', 'loglevel').upper(), None)
if not isinstance(numeric_level, int):
    raise ValueError('Invalid log level: %s' % config.get('process', 'loglevel'))
logging.basicConfig(level=numeric_level, filename=config.get('process', 'logfile', fallback=None))


if not os.path.isdir(config.get('paths', 'spooldir')):
    raise Exception('spooldir (%s) not found' % config.get('paths', 'spooldir'))

spooldir = {}
for folder in ['tmp', 'state', 'original', 'processed']:
    spooldir[folder] = os.path.abspath(config.get('paths', folder,
                                                  fallback=os.path.join(config.get('paths', 'spooldir'), folder)))
    os.makedirs(spooldir[folder], exist_ok=True)

productions = []
for inputfile in sys.argv[1:]:
    if not os.path.isfile(inputfile):
        logging.error('skipping %s as it is not a regular file' % inputfile)
        continue
    logging.info('Processing %s' % inputfile)

    backupfile = os.path.join(spooldir['original'], os.path.basename(inputfile))
    logging.debug('Backing up original to %s' % backupfile)
    try:
        shutil.copy2(inputfile, backupfile)
    except OSError as e:
        logging.exception('Failed to backup up original file to %s: %s' % (backupfile, e))
        exit(1)

    logging.debug('creating auphonic production')
    try:
        production = AuphonicProduction.new(auphonic_accesstoken, preset=config.get('auphonic', 'preset'),
                                            webhook=config.get('auphonic', 'webhook', fallback=None))
    except RuntimeError as e:
        logging.exception('Failed to create auphonic production: %s' % e)
        exit (1)
    productiondir = os.path.join(spooldir['tmp'], production.uuid)
    statefile = os.path.join(spooldir['state'], '%s.json' % production.uuid)
    logging.debug('created auphonic production with uuid %s, creating tmp dir %s and statefile %s'
                  % (production.uuid, productiondir, statefile))
    try:
        os.mkdir(productiondir)
    except OSError as e:
        logging.exception('Failed to create productiondir %s: %s' % (productiondir, e))
        exit(1)

    try:
        statefh = open(statefile, 'w')
    except OSError as e:
        logging.exception('Failed to create statefile %s: %s', (statefile, e))
        exit(1)

    uploadfile = backupfile
    fileformat = inputfile.split('.')[-1]
    soxinputargs = config.get('sox', 'fileformat_%s' % fileformat, fallback=None )
    soxoutputfile = None
    if soxinputargs is not None:
        soxoutputfile = '%s.%s' % (os.path.basename(inputfile).rsplit('.', maxsplit=1)[0],
                                   config.get('sox', 'outputfiletype', fallback='flac'))
        soxoutputfile = os.path.join(productiondir, soxoutputfile)
        logging.debug('sox outputfile: %s' % soxoutputfile)
        soxargs = [config.get('sox', 'sox', fallback='sox')]
        soxargs += shlex.split(soxinputargs)
        soxargs.append(uploadfile)
        soxargs += shlex.split(config.get('sox', 'output', fallback='-t %s "%s"')
                               % (soxoutputfile.split('.')[-1], shlex.quote(soxoutputfile)))
        logging.debug('running %s' % ' '.join(soxargs))
        try:
            sox = subprocess.run(soxargs, check=True)
        except subprocess.CalledProcessError as e:
            logging.exception('Failed to run sox, cmdline: %s, stderr: %s, stdout:%s' %
                              (e.cmd, (e.stderr if not None else ''), (e.output if not None else '')))
            exit(1)
        uploadfile = soxoutputfile

    logging.debug('Uploading %s' % uploadfile)
    try:
        production.upload(uploadfile)
    except RuntimeError as e:
        logging.exception('failed to upload %s to auphonic production %s: %s' % (uploadfile, production.uuid, e))
        exit(1)
    logging.debug('starting auphonic production')
    try:
        production.start()
    except RuntimeError as e:
        logging.exception('failed to start auphonic production %s: %s' % (production.uuid, e))
        exit(1)

    state = {
        'uuid': production.uuid,
        'inputfile': inputfile,
        'backupfile': backupfile,
        'sox': (soxinputargs is not None),
        'soxinputargs': soxinputargs,
        'soxoutputfile': soxoutputfile,

    }
    json.dump(state, statefh)
    statefh.close()

    productions.append(production)
print(' '.join(p.uuid for p in productions))