#!/usr/bin/env python3

from urllib.request import urlopen
import pathlib
import json
import sys

COMMIT = "d98cad66639bf9d0822129c4bcae7a169fcf9ca6"
BASE_URL = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/%s/gen-val/json-files" % COMMIT

KEY_GEN_URL = BASE_URL + "/SLH-DSA-keyGen-FIPS205/internalProjection.json"
SIG_GEN_URL = BASE_URL + "/SLH-DSA-sigGen-FIPS205/internalProjection.json"
SIG_VER_URL = BASE_URL + "/SLH-DSA-sigVer-FIPS205/internalProjection.json"

def is_supported_params(parameter_set):
  return parameter_set.endswith('SHA2-128s')

def download_test_vector(url, fname):
  print('Downloading test vectors from %s ...' % url, end='')
  sys.stdout.flush()
  with urlopen(url) as resp:
    resp_data = json.loads(resp.read())
    test_groups = [t for t in resp_data['testGroups'] if is_supported_params(t['parameterSet'])]
    with open(fname, 'w') as fh:
      json.dump(test_groups, fh)
  print(" done")

if __name__ == "__main__":
  pathlib.Path("tests/vectors").mkdir(parents=True, exist_ok=True)
  download_test_vector(KEY_GEN_URL, "tests/vectors/keygen.json"),
  download_test_vector(SIG_GEN_URL, "tests/vectors/signing.json"),
  download_test_vector(SIG_VER_URL, "tests/vectors/verifying.json"),
  print('OK')
