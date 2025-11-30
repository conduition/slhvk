#!/usr/bin/env python3

from urllib.request import urlopen
import argparse
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

def process_test_vector_data(raw_json_bytes):
  resp_data = json.loads(raw_json_bytes)
  test_groups = [t for t in resp_data['testGroups'] if is_supported_params(t['parameterSet'])]
  return test_groups

def write_filtered_vectors(raw_bytes, fname, etag=None):
  test_groups = process_test_vector_data(raw_bytes)
  with open(fname, 'w') as fh:
    json.dump(test_groups, fh)
  if etag is not None:
    with open(fname + '.etag', 'w') as fh:
      fh.write(etag)

def download_test_vector(url, fname):
  print('Downloading test vectors from %s ...' % url)
  sys.stdout.flush()

  old_etag = ""
  try:
    with open(fname + '.etag') as fh:
      old_etag = fh.read()
  except:
    pass

  with urlopen(url) as resp:
    new_etag = resp.headers.get('etag') or ""

    # Only download if file is changed
    if old_etag == "" or new_etag != old_etag:
      write_filtered_vectors(resp.read(), fname, etag=new_etag)

  print('test vectors saved to %s' % fname)

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("--keygen", help="Path to local keygen JSON (raw ACVP) to use instead of download")
  parser.add_argument("--signing", help="Path to local signing JSON (raw ACVP) to use instead of download")
  parser.add_argument("--verifying", help="Path to local verifying JSON (raw ACVP) to use instead of download")
  args = parser.parse_args()

  pathlib.Path("tests/vectors").mkdir(parents=True, exist_ok=True)
  if args.keygen:
    write_filtered_vectors(pathlib.Path(args.keygen).read_bytes(), "tests/vectors/keygen.json")
  else:
    download_test_vector(KEY_GEN_URL, "tests/vectors/keygen.json")

  if args.signing:
    write_filtered_vectors(pathlib.Path(args.signing).read_bytes(), "tests/vectors/signing.json")
  else:
    download_test_vector(SIG_GEN_URL, "tests/vectors/signing.json")

  if args.verifying:
    write_filtered_vectors(pathlib.Path(args.verifying).read_bytes(), "tests/vectors/verifying.json")
  else:
    download_test_vector(SIG_VER_URL, "tests/vectors/verifying.json")
  print('OK')
