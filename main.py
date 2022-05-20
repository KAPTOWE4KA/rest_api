# Получим репозитории по параметрам

import requests
import pprint
import json

token_needed = False

# Получение репозиториев

# result = requests.get('https://api.github.com/search/repositories?q=tetris+language:assembly&sort=stars&order=desc')
#
# pprint.pprint(result.json()['total_count'])
#
# params = {
#     'q': 'tetris+language:assembly',
#     'sort': 'stars',
#     'order': 'desc'
# }
#
#
# result = requests.get('https://api.github.com/search/repositories', params=params)
#
# print(result.url)
#
# pprint.pprint(result.json()['total_count'])

# Поиск кода

# https://api.github.com/search/code?q=addClass+in:file+language:js+repo:jquery/jquery

# Авторизация
session = requests.Session()
if token_needed:
    token_file = open("token.txt", "r", encoding="utf-8")
    token = str(token_file.readline())
    if len(token) > 2:
        print("Token used")
        session.auth = ('KAPTOWE4KA', token)

user = 'KAPTOWE4KA'
user = 'DanteOnline'
search_keywords = ['eval', 'sqllite3', 'pickle', 'login', 'mail', 'password']

url = 'https://api.github.com/search/code?q=eval+language:python+in:file+user:DanteOnline'

result = session.get(url)
print("Searching: "+str(result.status_code))
items = result.json()['items']
if len(items) < 1:
    print("No repos found with current parameters. Printing response json:")
    pprint.pprint(result.json())
    exit(1)

for item in items:
    if not item['path'].startswith('venv'):
        pprint.pprint(item['name'])
        pprint.pprint(item['repository']['full_name'].__str__()+"/"+item['path'].__str__())
        file_path_url = item['repository']['contents_url'].__str__().replace("{+path}", item['path'])
        pprint.pprint(file_path_url)



result = session.get(file_path_url)
print(result.status_code)
item = result.json()
pprint.pprint(item['download_url'])
result = session.get(item['download_url'])
print(result.text)

#file1 = open("newfile.py", "w", encoding="utf-8")
#file1.write(result.text)
