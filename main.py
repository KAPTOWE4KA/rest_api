# Получим репозитории по параметрам
import time

import requests
import pprint
import json

def split2(myline ,start, end):
    res = ""
    recording = False
    for char in myline:
        if char == start:
            recording = True
        elif char == end:
            recording = False
            return res
        if recording:
            res += char
    return res

def is_input_variable(variable, code_lns):
    for ln in code_lns:
        if variable in ln:
            if "input" in ln or ".read" in ln:
                return True
    return False

token_needed = False
user = 'KAPTOWE4KA'

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
if token_needed:#token_needed поставил в False так как с токеном не работает api.github
    token_file = open("token.txt", "r", encoding="utf-8")
    token = str(token_file.readline())
    if len(token) > 2:
        print("Token used")
        session.auth = (user, token)


danger_keywords = ['eval', 'sql', 'pickle', 'login', 'email', 'password', 'EMAIL_HOST_USER', 'EMAIL_HOST_PASSWORD', 'MIDDLEWARE_CLASSES', '@csrf_exempt']

unsafe_repos = {}
for keywd in danger_keywords:
    unsafe_repos[keywd] = {}
    time.sleep(0.5)
    url = f'https://api.github.com/search/code?q="{keywd}"+in:file+language:python+user:{user}'
    #https://api.github.com/search/code?q=%22EMAIL_HOST_USER%22+in:file+language:python+user:KAPTOWE4KA
    search_result = session.get(url)
    if search_result.status_code != 200:
        print("Invalid response: ")
        pprint.pprint(search_result.json())
        continue
    items = search_result.json()['items']
    if search_result.json()['total_count'] == 0:
        print("No repos found with current parameters. Printing response json:")
        pprint.pprint(search_result.json())
        print(f"Уязвимостей связанных с {keywd} не обнаружено в репозиториях пользователя {user}")
    else:
        for item in items:
            if not item['path'].startswith('venv') and item['repository']['name'] != "rest_api":
                if item['repository']['name'] not in unsafe_repos[keywd].keys():
                    unsafe_repos[keywd][item['repository']['name']] = {}
                #print(""+str(item['name']))
                pprint.pprint(f"Found {keywd} in {item['repository']['full_name'].__str__()}/{item['path'].__str__()}")
                file_path_url = item['repository']['contents_url'].__str__().replace("{+path}", item['path'])
                time.sleep(0.3)
                file_path_response = session.get(file_path_url)
                if file_path_response.status_code == 200:
                    unsafe_repos[keywd][item['repository']['name']][item['name']] = file_path_response.json()['download_url']

print(json.dumps(unsafe_repos, indent=2))


analysis_dict = {}

for keywd in unsafe_repos.keys():
    if unsafe_repos[keywd].keys().__len__() == 0:
        continue
    if keywd == 'eval':
        for repos in unsafe_repos[keywd].keys():
            if f"https://github.com/{user}/{repos}" not in analysis_dict.keys():
                analysis_dict[f"https://github.com/{user}/{repos}"] = {'words': [], 'unsafe_modules': []}

            if 'python' not in analysis_dict[f"https://github.com/{user}/{repos}"]['words']:
                analysis_dict[f"https://github.com/{user}/{repos}"]['words'].append('python')

            for file_key in unsafe_repos[keywd][repos].keys():
                time.sleep(0.5)
                result = session.get(unsafe_repos[keywd][repos][file_key])#download_url to variable
                code_lines = result.text.split('\n')
                eval_argument = ""
                for line in code_lines:
                    if "eval(" in line:
                        eval_argument = split2(line.split('eval'), '(', ')')
                        if is_input_variable(eval_argument, code_lines) or "input(" in line:
                            analysis_dict[f"https://github.com/{user}/{repos}"]['unsafe_modules'].append(
                                {'name': file_key, 'unsafe code type': 'В коде eval принимает данные из стороннего источника',
                                 'status': 'Содержит уязвимость'})
                        else:
                            analysis_dict[f"https://github.com/{user}/{repos}"]['unsafe_modules'].append(
                                {'name': file_key, 'unsafe code type': 'В коде используется eval',
                                 'status': 'Потенциально опасен'})

    elif keywd == 'pickle':
        for repos in unsafe_repos[keywd].keys():
            if f"https://github.com/{user}/{repos}" not in analysis_dict.keys():
                analysis_dict[f"https://github.com/{user}/{repos}"] = {'words': [], 'unsafe_modules': []}

            if 'python' not in analysis_dict[f"https://github.com/{user}/{repos}"]['words']:
                analysis_dict[f"https://github.com/{user}/{repos}"]['words'].append('python')

            for file_key in unsafe_repos[keywd][repos].keys():
                time.sleep(0.5)
                result = session.get(unsafe_repos[keywd][repos][file_key])  # download_url to variable
                code_lines = result.text.split('\n')
                eval_argument = ""
                for line in code_lines:
                    if "pickle.load(" in line:
                        eval_argument = split2(line.split('pickle.load'), '(', ')')
                        if is_input_variable(eval_argument, code_lines) or "input(" in line:
                            analysis_dict[f"https://github.com/{user}/{repos}"]['unsafe_modules'].append(
                                {'name': file_key,
                                 'unsafe code type': 'В коде pickle.load принимает данные из стороннего источника',
                                 'status': 'Содержит уязвимость'})
                        else:
                            analysis_dict[f"https://github.com/{user}/{repos}"]['unsafe_modules'].append(
                                {'name': file_key, 'unsafe code type': 'В коде используется pickle',
                                 'status': 'Потенциально опасен'})

    elif keywd == 'sql':
        for repos in unsafe_repos[keywd].keys():
            if f"https://github.com/{user}/{repos}" not in analysis_dict.keys():
                analysis_dict[f"https://github.com/{user}/{repos}"] = {'words': [], 'unsafe_modules': []}

            if 'python' not in analysis_dict[f"https://github.com/{user}/{repos}"]['words']:
                analysis_dict[f"https://github.com/{user}/{repos}"]['words'].append('python')
            if 'SQL' not in analysis_dict[f"https://github.com/{user}/{repos}"]['words']:
                analysis_dict[f"https://github.com/{user}/{repos}"]['words'].append('SQL')

            for file_key in unsafe_repos[keywd][repos].keys():
                time.sleep(0.5)
                result = session.get(unsafe_repos[keywd][repos][file_key])  # download_url to variable
                code_lines = result.text.split('\n')
                eval_argument = ""
                for line in code_lines:
                    if ("f\'SELECT" in line or "f\'UPDATE" in line or "f\'INSERT" in line or "f\'DELETE" in line) and "sqlite3" in result.text:
                        analysis_dict[f"https://github.com/{user}/{repos}"]['unsafe_modules'].append(
                            {'name': file_key,
                             'unsafe code type': 'В коде есть sql инъекция и прямой запрос к БД',
                             'status': 'Содержит уязвимость'})
                    elif ("f\'SELECT" in line or "f\'UPDATE" in line or "f\'INSERT" in line or "f\'DELETE" in line) and "sqlite3" not in result.text:
                        analysis_dict[f"https://github.com/{user}/{repos}"]['unsafe_modules'].append(
                            {'name': file_key, 'unsafe code type': 'В коде есть sql инъекция',
                             'status': 'Потенциально опасен'})

    elif keywd in ['login', 'email', 'password']:
        for repos in unsafe_repos[keywd].keys():
            if f"https://github.com/{user}/{repos}" not in analysis_dict.keys():
                analysis_dict[f"https://github.com/{user}/{repos}"] = {'words': [], 'unsafe_modules': []}

            if 'python' not in analysis_dict[f"https://github.com/{user}/{repos}"]['words']:
                analysis_dict[f"https://github.com/{user}/{repos}"]['words'].append('python')

            for file_key in unsafe_repos[keywd][repos].keys():
                time.sleep(0.5)
                result = session.get(unsafe_repos[keywd][repos][file_key])  # download_url to variable
                code_lines = result.text.split('\n')
                for line in code_lines:
                    if keywd in line and "=" in line and ("\"" in line or "\'" in line):
                        analysis_dict[f"https://github.com/{user}/{repos}"]['unsafe_modules'].append(
                            {'name': file_key,
                             'unsafe code type': f'В коде явно указано поле {keywd}',
                             'status': 'Содержит уязвимость'})

    elif keywd in ['EMAIL_HOST_USER', 'EMAIL_HOST_PASSWORD']:
        for repos in unsafe_repos[keywd].keys():
            if f"https://github.com/{user}/{repos}" not in analysis_dict.keys():
                analysis_dict[f"https://github.com/{user}/{repos}"] = {'words': [], 'unsafe_modules': []}

            if 'python' not in analysis_dict[f"https://github.com/{user}/{repos}"]['words']:
                analysis_dict[f"https://github.com/{user}/{repos}"]['words'].append('python')
            if 'django' not in analysis_dict[f"https://github.com/{user}/{repos}"]['words']:
                analysis_dict[f"https://github.com/{user}/{repos}"]['words'].append('django')

            for file_key in unsafe_repos[keywd][repos].keys():
                time.sleep(0.5)
                result = session.get(unsafe_repos[keywd][repos][file_key])  # download_url to variable
                code_lines = result.text.split('\n')
                for line in code_lines:
                    if keywd in line:
                        analysis_dict[f"https://github.com/{user}/{repos}"]['unsafe_modules'].append(
                            {'name': file_key,
                             'unsafe code type': f'В коде явно указано поле {keywd}',
                             'status': 'Содержит уязвимость'})

    elif keywd == 'MIDDLEWARE_CLASSES':
        for repos in unsafe_repos[keywd].keys():
            if f"https://github.com/{user}/{repos}" not in analysis_dict.keys():
                analysis_dict[f"https://github.com/{user}/{repos}"] = {'words': [], 'unsafe_modules': []}

            if 'python' not in analysis_dict[f"https://github.com/{user}/{repos}"]['words']:
                analysis_dict[f"https://github.com/{user}/{repos}"]['words'].append('python')
            if 'django' not in analysis_dict[f"https://github.com/{user}/{repos}"]['words']:
                analysis_dict[f"https://github.com/{user}/{repos}"]['words'].append('django')

            for file_key in unsafe_repos[keywd][repos].keys():
                time.sleep(0.5)
                result = session.get(unsafe_repos[keywd][repos][file_key])  # download_url to variable
                if "django.middleware.csrf.CsrfViewMiddleware" in result.text:
                    code_lines = result.text.split('\n')
                    for line in code_lines:
                        if "#django.middleware.csrf.CsrfViewMiddleware" in line or ((line.find("django.middleware.csrf.CsrfViewMiddleware") > line.find("#")) and line.find("#") > -1):
                            analysis_dict[f"https://github.com/{user}/{repos}"]['unsafe_modules'].append(
                                {'name': file_key,
                                 'unsafe code type': 'В коде закомментирован csrf token',
                                 'status': 'Потенциально опасен'})
                else:
                    analysis_dict[f"https://github.com/{user}/{repos}"]['unsafe_modules'].append(
                        {'name': file_key,
                         'unsafe code type': 'В коде отключен csrf token',
                         'status': 'Потенциально опасен'})

    elif keywd == '@csrf_exempt':
        for repos in unsafe_repos[keywd].keys():
            if f"https://github.com/{user}/{repos}" not in analysis_dict.keys():
                analysis_dict[f"https://github.com/{user}/{repos}"] = {'words': [], 'unsafe_modules': []}

            if 'python' not in analysis_dict[f"https://github.com/{user}/{repos}"]['words']:
                analysis_dict[f"https://github.com/{user}/{repos}"]['words'].append('python')
            if 'django' not in analysis_dict[f"https://github.com/{user}/{repos}"]['words']:
                analysis_dict[f"https://github.com/{user}/{repos}"]['words'].append('django')

            for file_key in unsafe_repos[keywd][repos].keys():
                time.sleep(0.5)
                result = session.get(unsafe_repos[keywd][repos][file_key])  # download_url to variable
                if "#@csrf_exempt" in result.text:
                    break
                else:
                    analysis_dict[f"https://github.com/{user}/{repos}"]['unsafe_modules'].append(
                        {'name': file_key,
                         'unsafe code type': 'В коде локально отключен csrf token. В коде проекта используется декоратор @csrf_exempt',
                         'status': 'Потенциально опасен'})

pprint.pprint(json.dumps(analysis_dict, indent=4).encode(encoding="utf-8"))

with open('analysis_dict.json', 'w', encoding='utf8') as json_file:
    json.dump(analysis_dict, json_file, ensure_ascii=False, indent=4)
#print(result.text)

#result = session.get(item['download_url'])
#file1 = open("newfile.py", "w", encoding="utf-8")
#file1.write(result.text)
