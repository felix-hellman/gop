import requests
import json
import webbrowser
from gop import Server, Handler


class ApiClient:
    def __init__(self, token, baseUrl):
        self.token = token
        self.baseUrl = baseUrl

    def __load_token_header(self):
        return {"Authorization": "Bearer " + self.token, "Content-Type": "application/json"}

    def ping(self):
        r = requests.post(self.baseUrl + "/ping", headers=self.__load_token_header())
        return r.status_code == 200

    def upload_public_key(self, encoded_key):
        data = json.dumps({'public_key': encoded_key, 'force_upload': False})
        r = requests.post(self.baseUrl + "/key/add", data=data, headers=self.__load_token_header())
        return r.status_code == 200

    def login(self, repo):
        response = requests.get(self.baseUrl + "/login/github/init" + {True: "?scope=repo", False: ""}[repo])
        webbrowser.open(str(response.content, 'utf-8'))
        with Server(("", 1337), Handler) as httpd:
            httpd.handle_request()
