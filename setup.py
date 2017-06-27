from setuptools import setup, find_packages
import io
import os
import re


# Example code to pull version from esptool.py with regex, taken from
# https://packaging.python.org/guides/single-sourcing-package-version/
def read(*names, **kwargs):
    with io.open(
            os.path.join(os.path.dirname(__file__), *names),
            encoding=kwargs.get("encoding", "utf8")
    ) as fp:
        return fp.read()


def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")

setup(
  name = 'asterisk_mbox_server',
  packages=find_packages(),
  version=find_version("asterisk_mbox_server", "__init__.py"),
  description = 'The server portion of a client/server to interact with Asterisk voicemail mailboxes',
  long_description=open('README.rst').read(),
  author = 'PhracturedBlue',
  author_email = 'rc2012@pblue.org',
  url = 'https://github.com/PhracturedBlue/asterisk_mbox_server', # use the URL to the github repo
  keywords = ['testing', 'asterisk' 'mailbox', 'voicemail'], # arbitrary keywords
  classifiers = [],
  install_requires=[
        "inotify",
        "SpeechRecognition",
        "asterisk_mbox",
   ],
   entry_points = {
        'console_scripts': [
            'asterisk-mbox-server = asterisk_mbox_server:main'
        ]
   },

)
