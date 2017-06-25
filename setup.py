from setuptools import setup, find_packages
setup(
  name = 'asteriskvm_server',
  packages=find_packages(),
  version = '0.2.1',
  description = 'The server portion of a client/server to interact with Asterisk voicemail mailboxes',
  long_description=open('README.rst').read(),
  author = 'PhracturedBlue',
  author_email = 'rc2012@pblue.org',
  url = 'https://github.com/PhracturedBlue/asteriskvm_server', # use the URL to the github repo
  keywords = ['testing', 'asterisk'], # arbitrary keywords
  classifiers = [],
  install_requires=[
        "inotify",
        "SpeechRecognition",
        "asteriskvm",
   ],
   entry_points = {
        'console_scripts': [
            'asteriskvm-server = asteriskvm_server:main'
        ]
   },

)
