import urllib.parse
import urllib.request

target_url = "{{TARGET_URL}}"
param_name = "{{PARAM_NAME}}"
redirect_url = "{{REDIRECT_URL}}"

params = {param_name: redirect_url}
url = target_url + "?" + urllib.parse.urlencode(params)


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        return None


try:
    opener = urllib.request.build_opener()
    with opener.open(url) as response:
        if response.geturl() == redirect_url:
            print(f"VERIFIED: Final URL matches redirect destination")
            exit(0)
except Exception as e:
    print(f"ERROR: {e}")

print("NOT VERIFIED")
exit(1)
