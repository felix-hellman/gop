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

    def upload_package(self, payload, manifest):
        package_name = str(manifest["project"]["package"]["name"])
        version = str(manifest["project"]["package"]["version"])
        data = json.dumps({"jwt": payload, 'package_name': package_name, 'version': version})
        r = requests.post(self.baseUrl + "/pkg/add", data=data, headers=self.__load_token_header())
        return r.status_code == 200

    def login(self, repo):
        response = requests.get(self.baseUrl + "/login/github/init" + {True: "?scope=repo", False: ""}[repo])
        webbrowser.open(str(response.content, 'utf-8'))
        with Server(("", 1337), Handler) as httpd:
            httpd.handle_request()

    def fetch_public_dependency(self, dependency):
        p = self.baseUrl + "/pkg/fetch/" + dependency["name"] + "/" + dependency["version"]
        r = requests.get(p, headers={"Content-Type": "application/json"})
        assert r.status_code == 200, F"Failed to fetch public package : {r.status_code}"
        return json.loads(r.content)

    def fetch_private_dependency(self, dependency):
        r = requests.get(self.baseUrl + F"/pkg/github/{dependency['name']}", headers=self.__load_token_header())
        assert r.status_code == 200, "Failed to fetch private package, probably due to invalid scope"
        return str(r.content, 'utf-8')

    def fetch_public_key(self, author):
        r = requests.get(self.baseUrl + "/key/" + author, headers={"Content-Type": "application/json"})
        assert r.status_code == 200, F"Failed to fetch public key : {r.status_code}"
        return json.loads(r.content)

    def fetch_versions(self, dependency):
        full_path = dependency['version'] + "/pkg/list/" + dependency['name']
        r = requests.get(full_path, headers={"Content-Type": "application/json"})
        assert r.status_code == 200, F"Failed to fetch version list : {r.status_code}"
        return json.loads(r.content)

    def search(self, author):
        r = requests.get(self.baseUrl + "/pkg/list/" + str(author), headers={"Content-Type": "application/json"})
        assert r.status_code == 200, F"Failed to fetch search results : {r.status_code}"
        return json.loads(r.content)