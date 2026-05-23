import urllib.parse
import urllib.request

target_url = "{{TARGET_URL}}"
param_name = "{{PARAM_NAME}}"
payload = "{{PAYLOAD}}"

sql_errors = [
    "syntax error",
    "ORA-",
    "mysql_fetch",
    "PostgreSQL query failed",
    "SQLite3::SQLException",
    "Dynamic SQL Error",
    "SQLState:",
]

params = {param_name: payload}
data = urllib.parse.urlencode(params).encode()
req = urllib.request.Request(target_url, data=data)

try:
    with urllib.request.urlopen(req) as response:
        body = response.read().decode("utf-8", errors="ignore")
        for error in sql_errors:
            if error in body:
                print(f"VERIFIED: Found SQL error string: {error}")
                exit(0)
except Exception as e:
    body = str(e)
    for error in sql_errors:
        if error in body:
            print(f"VERIFIED: Found SQL error string in exception: {error}")
            exit(0)

print("NOT VERIFIED")
exit(1)
