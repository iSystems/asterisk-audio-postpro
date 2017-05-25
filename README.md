# asterisk-audio-postpro

automated audio post-processing/production for asterisk or other pbx systems

**this procjet is under active development, expect broken code, a first working verion is found under tag `v0.0.1`.**

## dependencies 
- [Python 3.6](https://www.python.org/)
- [Python Requests](http://docs.python-requests.org/)
- [sox](http://sox.sourceforge.net/)
- [Auphonic](https://auphonic.com/)

## installation
- Loook at the example config and customize it to your needs
- Create an desktop app on [Auphonic](https://auphonic.com/api/apps/) to get an oauth2 clientid and secret
- put the oauth2 clientid and secret in the config file
- run register_oauth.py to get an oauth2 accesstoken and put it into the configuration

## usage
Start server.py, the user under which you run it has to have write access to the audio files youre working with
when one or more audio files need to be postprocessed run ``postprocess.py [file] [file] ...``