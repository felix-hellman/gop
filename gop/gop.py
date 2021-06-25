#! /usr/bin/python3

import click
import requests
from easysettings import EasySettings
import yaml
import re
import hashlib
import python_jwt as jwt, jwcrypto.jwk as jwk, datetime
import os
import shutil
import base64
import json
from gop import ApiClient
from gop import FileLayer

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

settings = EasySettings("gop.conf")

VERSION_REGEX = "^([0-9\\.]+|latest)$"
PATH_REGEX = "^(http[s]{0,1}:\\/\\/[a-zA-Z0-9\\.]+(:[0-9]+){0,1}|([0-9]{1,3}\\.){3}[0-9](:[0-9]+){0,1})$"
BASE = "https://gop.shrimpray.com"


@click.group()
def cli():
    pass


def generate_yaml_lines(name, author, version):
    lines = ['project:\n']
    if name is not None and author is not None and version is not None:
        lines.append('  package:\n')
        lines.append('    name: ' + name + '\n')
        lines.append('    author: ' + author + '\n')
        lines.append('    version: ' + version + '\n')
    lines.append('  dependencies:\n')
    lines.append('  repository:\n')
    lines.append('    - path: ' + BASE + '\n')

    return lines

@cli.command('init')
@click.option("--name", required=False)
@click.option('--author', required=False)
@click.option('--version', required=False)
def init_project(name, author, version):
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
        f.writelines(generate_yaml_lines(name, author, version))


def unpack(token):
    package = token["package"]
    dependencies = token["manifest"]["project"]["dependencies"]
    manifest = token["manifest"]
    if dependencies is None:
        dependencies = []
    binary_data = b64_decode_string(package)
    os.makedirs(format_pkg_path(manifest), exist_ok=True)
    with open('pkg.zip', 'wb') as f:
        f.write(binary_data)
    shutil.unpack_archive('pkg.zip', format_pkg_path(manifest))
    os.remove('pkg.zip')
    return dependencies


def fetch_dependency(repository, dependency):
    version = str(dependency["version"])
    path = str(repository["path"])
    assert re.match(VERSION_REGEX, version), "Invalid version numbering"
    assert re.match(PATH_REGEX, path)
    p = path + "/pkg/fetch/" + dependency["name"] + "/" + version
    r = requests.get(p, headers={"Content-Type": "application/json"})
    response = json.loads(r.content)
    author = response["author"]
    jwt = response["jwt"]
    trust_dict = settings.get('trust-list', default={})
    if author not in trust_dict.keys():
        print("You don't have this authors public key, do you want to trust this key?")
        fetched_key = json.loads(
            requests.get(path + "/key/" + author, headers={"Content-Type": "application/json"}).content)
        decoded_key = b64_decode_string(fetched_key["publicKey"])
        print(decoded_key)
        print("\n\n\nDo you want to trust this key? Y/N\n\n")
        choice = input()
        if choice[0] == 'Y' or choice[0] == 'y':
            trust_dict[author] = decoded_key
            settings.set('trust-list', trust_dict)
            settings.save()
            pass
    key = trust_dict[author]
    validated = validate_jwt(jwt, key)
    return unpack(validated)


def post_package(manifest, payload):
    path = str(manifest["project"]["repository"][0]['path'])
    package_name = str(manifest["project"]["package"]["name"])
    version = str(manifest["project"]["package"]["version"])
    payload=json.dumps({"jwt": payload, 'package_name': package_name, 'version': version})
    r = requests.post(path + "/pkg/add",data=payload, headers=load_token_header())
    if r.status_code == 200:
        print("Package was successfully uploaded")
    else:
        print("Failed to upload package")


def load_token_header():
    token = settings.get("token")
    return {"Authorization": "Bearer " + token, "Content-Type": "application/json"}


def is_logged_in():
    r = requests.post(BASE + "/ping", headers=load_token_header())
    return r.status_code == 200



def create_api_client():
    token = settings.get("token")
    return ApiClient(token, BASE)

@cli.command('ping')
def ping():
    if create_api_client().ping():
        print("You are logged in")
    else:
        print("You are not logged in")


@cli.command('upload-key')
@click.option('--key-file', type=click.Path(exists=True, readable=True, path_type=str), required=True)
def upload_key(key_file):
    encoded_key = FileLayer().b64_encode_file(key_file)
    if create_api_client().upload_public_key(encoded_key):
        print("Key uploaded successfully")
    else:
        print("Failed to upload public key")


@cli.command('add')
@click.option('--dependency', required=True)
@click.option('--version', required=True)
def add_pkg(dependency, version):
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


@cli.command('search')
@click.option('--author', required=True)
def search(author):
    manifest = parse_yaml("manifest.yaml")
    path = str(manifest["project"]["repository"][0]["path"])
    r = requests.get(path + "/pkg/list/" + str(author), headers={"Content-Type": "application/json"})
    matches = json.loads(r.content)
    for match in matches:
        print(match)
        split_match = match.split("/")
        dependency , version = split_match[0] +"/"+ split_match[1], split_match[2]
        print(F"gop add --dependency={dependency} --version={version}\n")


@cli.command('update')
@click.option('--dry-run', required=False, count=True)
def update(dry_run):
    manifest = parse_yaml("manifest.yaml")
    path = str(manifest["project"]["repository"][0]["path"])
    updates = []
    for dependency in manifest['project']['dependencies']:
        name =  dependency['name']
        version = dependency['version']
        full_path = path + "/pkg/list/" + name
        versions = json.loads(requests.get(full_path).content)
        latest_version = sorted(versions).pop()
        if latest_version > version:
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



@cli.command('login')
@click.option('--token', required=False)
@click.option('--repo', required=False, count=True)
def login(token, repo):
    if token is None:
        create_api_client().login(repo)
    else:
        settings.set("token", token)
        settings.save()


@cli.command('logout')
def logout():
    settings.set("token", "")
    settings.save()
    print("Logged out")


def matching_dependency(dependency, l):
    for d in l:
        if d["name"] == dependency["name"]:
            left_version = d["version"]
            right_version = dependency["version"]
            if left_version is None:
                left_version = ""
            if right_version is None:
                right_version = ""
            assert d["version"] != dependency["version"], "Version missmatch aborting"


def fetch_dependencies(repository, dependencies, fetched):
    found_dependencies = []
    for dependency in dependencies:
        matching_dependency(dependency, fetched)
        fetched.append(dependency)
        if "access" in dependency.keys() and "private" in dependency["access"]:
            print("Fetching from github " + str(dependency))
            path = str(repository["path"])
            r = requests.get(path + F"/pkg/github/{dependency['name']}", headers=load_token_header())
            assert r.status_code == 200, "Failed to fetch private package, probably due to invalid scope"
            content = str(r.content, 'utf-8')
            data = b64_decode_string(content)
            with open('pkg.zip', 'wb') as f:
                f.write(data)
            split_name = dependency['name'].split('/')
            dep_name = split_name[0] + "-" + split_name[1]
            shutil.unpack_archive('pkg.zip', './tmp/' + dep_name)
            os.remove("pkg.zip")
            src =  "./tmp/" + dep_name + "/"+ split_name[1] +"-main" + "/pkg/" + dep_name
            dst = "./pkg/"
            shutil.move(src , dst)
            manifest = parse_yaml("./tmp/" + dep_name + "/"+ split_name[1] +"-main/manifest.yaml")
            for found in manifest["project"]["dependencies"]:
                if found not in dependencies:
                    found_dependencies.append(found)
        else:
            print("Fetching " + str(dependency))
            for found in fetch_dependency(repository, dependency):
                if found not in dependencies:
                    found_dependencies.append(found)
    return {"dependants": found_dependencies, "dependencies_fetched": fetched}


def format_pkg_path(manifest):
    author = manifest["project"]["package"]["author"]
    package_name = manifest["project"]["package"]["name"]
    return './pkg/' + author + "-" + package_name

@cli.command('install')
def install():
    with open('manifest.yaml') as document:
        manifest = yaml.load(document, Loader=Loader)
        repository = manifest["project"]["repository"][0]
        dependencies = manifest["project"]["dependencies"]
        depency_spec = {"dependants": dependencies, "dependencies_fetched": []}
        for pkg in os.listdir("./pkg"):
            author = manifest["project"]["package"]["author"]
            package_name = manifest["project"]["package"]["name"]
            main_pkg_name = author + "-" + package_name
            if main_pkg_name not in pkg:
                shutil.rmtree("./pkg/" + pkg)
        os.makedirs("./pkg", exist_ok=True)
        while len(depency_spec["dependants"]) > 0:
            depency_spec = fetch_dependencies(repository, depency_spec["dependants"],
                                              depency_spec["dependencies_fetched"])


@cli.command('trust-key')
@click.option('--key-file', type=click.Path(exists=True, readable=True, path_type=str), required=True)
def trust(key_file, author):
    key = read_key_from_file(key_file)
    trust_dict = settings.get('trust-list', default={})
    try:
        # Validate key
        jwk.JWK.from_pem(key)
        trust_dict[author] = key
        settings.save()
    except TypeError as e:
        print("Invalid key format, please use PEM formatting")
    pass


def read_key_from_file(key_file):
    with open(key_file, 'rb') as f:
        return f.read()


def hash_zip(zipped_file):
    package_hash = hashlib.sha512()
    with open(zipped_file, 'rb') as f:
        package_hash.update(f.read())
    return package_hash.hexdigest()


def b64_encode_file(path):
    with open(path, 'rb') as f:
        return base64.b64encode(f.read())


def b64_decode_string(value):
    return base64.b64decode(value)


def pack(directory, key, author, manifest):
    shutil.make_archive('pkg', 'zip', directory)
    b64 = b64_encode_file('pkg.zip')
    package_hash = hash_zip('pkg.zip')
    os.remove('pkg.zip')
    payload = {'package': str(b64, 'utf-8'), 'package_hash': package_hash, 'author': author, 'manifest': manifest}
    return sign_payload(payload, key)


def sign_payload(payload, pem):
    private_key = jwk.JWK.from_pem(pem)
    return jwt.generate_jwt(payload, private_key, 'RS256', datetime.timedelta(days=99999))


def validate_jwt(token, pem):
    public_key = jwk.JWK.from_pem(pem)
    header, claims = jwt.verify_jwt(token, public_key, ['RS256'])
    return claims


def parse_yaml(manifest):
    with open(manifest) as document:
        return yaml.load(document, Loader=Loader)


@cli.command('package')
@click.option('--key-file', type=click.Path(exists=True, readable=True, path_type=str), required=True)
def package(key_file):
    key = read_key_from_file(key_file)
    manifest = parse_yaml('manifest.yaml')
    token = pack(format_pkg_path(manifest), key, manifest['project']['package']['author'], manifest)
    post_package(manifest, token)
    pass


@cli.command('generate-key-pair')
def generate_key_pair():
    key = jwk.JWK.generate(kty='RSA', size=2048)
    priv_pem = key.export_to_pem(private_key=True, password=None)
    pub_pem = key.export_to_pem()
    with open('../public-key.pem', 'wb') as f:
        f.write(pub_pem)
    with open('../private-key.pem', 'wb') as f:
        f.write(priv_pem)
    settings.save()


if __name__ == '__main__':
    cli()

def __main__():
    cli()