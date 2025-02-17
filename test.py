import requests

url = "http://127.0.0.1:5000/get_available_specs"
data = {"ram": 0}

response = requests.get(url)
print(response.json())