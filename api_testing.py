from idlelib.editor import keynames

import requests

url = "https://api.techspecs.io/v5/brands?category=Smartphones&page=0&size=10"

headers = {
    "accept": "application/json",
    "X-API-KEY": "fcc06703-87b2-4cef-843b-c8289de2dd25",
    "X-API-ID": "67b193ddb2d1928292d9fc59"
}

params = {
    "category": "Laptops",  # Change category to Laptops
    "page": 0,
    "size": 10
}

response = requests.get(url, headers=headers, params=params)
print(response.text)

# id
# 67b193ddb2d1928292d9fc59
# key
# fcc06703-87b2-4cef-843b-c8289de2dd25

#
# "X-API-KEY": "1ff710a4-8d99-43b3-9351-b7f842901f82",
# "X-API-ID": "67b196ddb2d1928292d9fc62"