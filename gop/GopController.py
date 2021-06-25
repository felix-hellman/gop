from easysettings import EasySettings
import yaml
import re
import python_jwt as jwt, jwcrypto.jwk as jwk, datetime
import os
import shutil
import base64

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

settings = EasySettings("gop.conf")

VERSION_REGEX = "^([0-9\\.]+|latest)$"
PATH_REGEX = "^(http[s]{0,1}:\\/\\/[a-zA-Z0-9\\.]+(:[0-9]+){0,1}|([0-9]{1,3}\\.){3}[0-9](:[0-9]+){0,1})$"

class GopController:

    def __init__(self, api, fileLayer):
        self.api = api
        self.fileLayer = fileLayer

    def generate_yaml_lines(self, name, author, version):
        lines = ['project:\n']
        if name is not None and author is not None and version is not None:
            lines.append('  package:\n')
            lines.append('    name: ' + name + '\n')
            lines.append('    author: ' + author + '\n')
            lines.append('    version: ' + version + '\n')
        lines.append('  dependencies:\n')
        lines.append('  repository:\n')
        lines.append('    - path: ' + "https://gop.shrimpray.com" + '\n')

        return lines

    def init_project(self, name, author, version):
        directories = ['pkg']
        if name is not None and author is not None and version is not None:
            directories.append('pkg/' + author + '-' + name)
        for directory in directories:
            os.makedirs("./" + directory, exist_ok=True)
        found_ignore = False
        if os.path.isfile('.gitignore'):
            with open('.gitignore', 'r') as f:
                for line in f.readlines():
                    if 'pkg\n' in line or 'gop.conf\n' in line:
                        found_ignore = True
        if not found_ignore:
            with open('.gitignore', 'a') as f:
                f.writelines(['pkg\n', 'gop.conf\n'])
        with open('manifest.yaml', 'w') as f:
            f.writelines(self.generate_yaml_lines(name, author, version))

    def fetch_public_dependency(self, repository, dependency):
        assert re.match(VERSION_REGEX, dependency["version"]), "Invalid version numbering"
        assert re.match(PATH_REGEX, repository["path"])
        response = self.api.fetch_public_dependency(dependency)
        author = response["author"]
        jwt = response["jwt"]
        trust_dict = settings.get('trust-list', default={})
        if author not in trust_dict.keys():
            print("You don't have this authors public key, do you want to trust this key?")
            fetched_key = self.api.fetch_public_key(author)
            decoded_key = self.b64_decode_string(fetched_key["publicKey"])
            print(decoded_key)
            print("\n\n\nDo you want to trust this key? Y/N\n\n")
            choice = input()
            if choice[0] == 'Y' or choice[0] == 'y':
                trust_dict[author] = decoded_key
                settings.set('trust-list', trust_dict)
                settings.save()
                pass
        key = trust_dict[author]
        validated = self.validate_jwt(jwt, key)
        return self.fileLayer.unpack_dependency(validated["package"], validated["manifest"])

    def load_token_header(self):
        token = settings.get("token")
        return {"Authorization": "Bearer " + token, "Content-Type": "application/json"}

    def ping(self):
        if self.api.ping():
            print("You are logged in")
        else:
            print("You are not logged in")

    def upload_key(self, key_file):
        encoded_key = self.fileLayer.b64_encode_file(key_file)
        if self.api.upload_public_key(encoded_key):
            print("Key uploaded successfully")
        else:
            print("Failed to upload public key")


    def add_pkg(self, dependency, version):
        assert re.match(VERSION_REGEX, version), "Invalid version numbering"
        with open('manifest.yaml') as document:
            manifest = yaml.load(document, Loader=Loader)
            if manifest['project']['dependencies'] is None:
                manifest['project']['dependencies'] = []
            found = False
            for dep in manifest['project']['dependencies']:
                if dep['name'] in dependency:
                    found = True
            if not found:
                manifest['project']['dependencies'].append({"name": dependency, "version": version})
            else:
                print(F"Dependency {dependency} already exists")
        with open('manifest.yaml', 'w') as f:
            yaml.dump(manifest, f)


    def search(self, author):
        for match in self.api.search(author):
            print(match)
            split_match = match.split("/")
            dependency, version = split_match[0] + "/" + split_match[1], split_match[2]
            print(F"gop add --dependency={dependency} --version={version}\n")


    def update(self, dry_run):
        manifest = self.fileLayer.parse_yaml("manifest.yaml")
        updates = []
        for dependency in manifest['project']['dependencies']:
            versions = self.api.fetch_versions(dependency)
            latest_version = sorted(versions).pop()
            version = dependency['version']
            if latest_version > version:
                name = dependency['name']
                updates.append(F"{name}/{version} => {name}/{latest_version}")
                dependency['version'] = latest_version

        if not dry_run:
            for update in updates:
                print(update)
            with open('manifest.yaml', 'w') as f:
                yaml.dump(manifest, f)
        else:
            for update in updates:
                print(update)
            print(yaml.dump(manifest))


    def login(self, token, repo):
        if token is None:
            self.api.login(repo)
        else:
            settings.set("token", token)
            settings.save()

    def logout(self):
        settings.set("token", "")
        settings.save()
        print("Logged out")

    def matching_dependency(self, dependency, l):
        for d in l:
            if d["name"] == dependency["name"]:
                left_version = d["version"]
                right_version = dependency["version"]
                if left_version is None:
                    left_version = ""
                if right_version is None:
                    right_version = ""
                assert d["version"] != dependency["version"], "Version missmatch aborting"

    def fetch_dependencies(self, repository, dependencies, fetched):
        found_dependencies = []
        for dependency in dependencies:
            self.matching_dependency(dependency, fetched)
            fetched.append(dependency)
            if "access" in dependency.keys() and "private" in dependency["access"]:
                print("Fetching from github " + str(dependency))
                content = self.api.fetch_private_dependency(dependency)
                self.fileLayer.save_b64_pkg_zip(content)
                self.fileLayer.unzip(dependency)
                manifest = self.fileLayer.load_dependency_manifest(dependency)
                for found in manifest["project"]["dependencies"]:
                    if found not in dependencies:
                        found_dependencies.append(found)
            else:
                print("Fetching " + str(dependency))
                for found in self.fetch_public_dependency(repository, dependency):
                    if found not in dependencies:
                        found_dependencies.append(found)
        return {"dependants": found_dependencies, "dependencies_fetched": fetched}

    def format_pkg_path(self, manifest):
        author = manifest["project"]["package"]["author"]
        package_name = manifest["project"]["package"]["name"]
        return './pkg/' + author + "-" + package_name

    def get_main_pkg(self, manifest):
        if "package" in manifest["project"].keys() is not None:
            author = manifest["project"]["package"]["author"]
            package_name = manifest["project"]["package"]["name"]
            return author + "-" + package_name
        return ""

    def install(self):
        with open('manifest.yaml') as document:
            manifest = yaml.load(document, Loader=Loader)
            repository = manifest["project"]["repository"][0]
            dependencies = manifest["project"]["dependencies"]
            depency_spec = {"dependants": dependencies, "dependencies_fetched": []}
            for pkg in os.listdir("./pkg"):
                main_pkg_name = self.get_main_pkg(manifest)
                if main_pkg_name not in pkg:
                    shutil.rmtree("./pkg/" + pkg)
            os.makedirs("./pkg", exist_ok=True)
            while len(depency_spec["dependants"]) > 0:
                depency_spec = self.fetch_dependencies(repository, depency_spec["dependants"],
                                                  depency_spec["dependencies_fetched"])


    def trust(self, key_file, author):
        key = self.read_key_from_file(key_file)
        trust_dict = settings.get('trust-list', default={})
        try:
            # Validate key
            jwk.JWK.from_pem(key)
            trust_dict[author] = key
            settings.save()
        except TypeError as e:
            print("Invalid key format, please use PEM formatting")
        pass

    def read_key_from_file(self, key_file):
        with open(key_file, 'rb') as f:
            return f.read()

    def b64_decode_string(self, value):
        return base64.b64decode(value)

    def pack(self, key, manifest):
        author = manifest['project']['package']['author']
        b64, package_hash = self.fileLayer.package_dependency(manifest)
        payload = {'package': str(b64, 'utf-8'), 'package_hash': package_hash, 'author': author, 'manifest': manifest}
        return self.sign_payload(payload, key)

    def sign_payload(self, payload, pem):
        private_key = jwk.JWK.from_pem(pem)
        return jwt.generate_jwt(payload, private_key, 'RS256', datetime.timedelta(days=99999))

    def validate_jwt(self, token, pem):
        public_key = jwk.JWK.from_pem(pem)
        header, claims = jwt.verify_jwt(token, public_key, ['RS256'])
        return claims


    def package(self, key_file):
        key = self.read_key_from_file(key_file)
        manifest = self.fileLayer.parse_yaml('manifest.yaml')
        token = self.pack(key, manifest)
        if self.api.upload_package(token, manifest):
            print("Package was successfully uploaded")
        else:
            print("Failed to upload package")

    def generate_key_pair(self):
        key = jwk.JWK.generate(kty='RSA', size=2048)
        priv_pem = key.export_to_pem(private_key=True, password=None)
        pub_pem = key.export_to_pem()
        with open('../public-key.pem', 'wb') as f:
            f.write(pub_pem)
        with open('../private-key.pem', 'wb') as f:
            f.write(priv_pem)
        settings.save()