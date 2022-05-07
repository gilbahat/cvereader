import boto3
import requests
import os
import sys
import json
import gzip
from datetime import date

s3 = boto3.client(service_name='s3')

current_year = date.today().year

CVES_AVAILABLE = [str(x) for x in list(range(2002, current_year))] + ["recent", "modified"]
NVD_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-"
STATEFILE = "cve.meta.state"

S3_BUCKET = os.environ.get('S3_BUCKET')

state_dict = {}

# request CVE metafiles
for x in CVES_AVAILABLE:
   # try requests, error neterror
   res = requests.get(NVD_BASE_URL + x + ".meta")  
   # try parse, error malformed
   sha256 = res.text.split("\r\n")[4].split(":")[1]
   state_dict[x] = sha256

# get latest status from S3
print(S3_BUCKET, STATEFILE)
s3.download_file(S3_BUCKET, STATEFILE, STATEFILE)
with open(STATEFILE, 'r') as f:
  s3_state_dict = json.load(f)

list_to_dl = []

# for every updated, get latest and store into s3
for x in state_dict:
   if not x in s3_state_dict:
      list_to_dl.append(x)
   else:
      if s3_state_dict[x] != state_dict[x]:
         list_to_dl.append(x)

# if no new files, no need to regenerate list
if not list_to_dl:
   print("nothing to dl. exiting")
   sys.exit(0)

cvelist = []

# now go over s3 again, regenerating entire list
for x in list_to_dl:
   req = requests.get(NVD_BASE_URL + x + ".json.gz")
   res = gzip.decompress(req.content).decode("utf-8")
   cves = json.loads(res)
   for cve in cves["CVE_Items"]:
      for dd in cve['cve']['description']['description_data']:
          if dd['lang'] == "en":
             if dd['value'].lower().find("jenkins") > -1:
                cvelist.append(cve)
             if dd['value'].lower().find("aws") > -1:
                cvelist.append(cve)
             if dd['value'].lower().find("kubernetes") > -1:
                cvelist.append(cve)
   

with open("cvelist", "w") as c:
  json.dump(cvelist, c)
c.close()

with open(STATEFILE, "w") as st:
  json.dump(state_dict, st)
st.close()

# upload list to s3
s3.upload_file("cvelist", S3_BUCKET, "cvelist")

# update state file
s3.upload_file(STATEFILE, S3_BUCKET, STATEFILE)
