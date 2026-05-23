import urllib.parse
import urllib.request
import uuid

target_url = "{{TARGET_URL}}"
param_name = "{{PARAM_NAME}}"
token = str(uuid.uuid4())
payload = f"{{PAYLOAD}} {token}"

params = {param_name: payload}
url = target_url + "?" + urllib.parse.urlencode(params)

try:
    with urllib.request.urlopen(url) as response:
        body = response.read().decode("utf-8", errors="ignore")
        if token in body:
            print(f"VERIFIED: Found echo token {token}")
            exit(0)
except Exception as e:
    print(f"ERROR: {e}")

print("NOT VERIFIED")
exit(1)
