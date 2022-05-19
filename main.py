# Получим репозитории по параметрам

import requests
import pprint

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
token = 'MY_TOKEN'
# 1.
# result = requests.get('https://api.github.com/search/code?q=addClass+in:file+language:js+repo:jquery/jquery', auth=('DanteOnline', token))
# 2.
# headers = {
#     'Authorization': f'token {token}'
# }
# result = requests.get('https://api.github.com/search/code?q=addClass+in:file+language:js+repo:jquery/jquery', headers=headers)

session = requests.Session()
session.auth = ('DanteOnline', token)

result = session.get('https://api.github.com/search/code?q=eval+in:file+language:python+user:DanteOnline')
print(result.status_code)
items = result.json()['items']

for item in items:
    if not item['path'].startswith('venv'):
        pprint.pprint(item)


