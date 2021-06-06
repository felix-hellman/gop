import click
import requests
from easysettings import EasySettings
import yaml
import re
import glob
import hashlib
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


@click.group()
def cli():
    pass


@cli.command('init')
def init_project():
    for directory in ['src', 'pkg', 'assets', 'managed-assets']:
        os.makedirs("./" + directory, exist_ok=True)
    with open('.gitignore', 'a') as f:
        f.writelines(['pkg\n', 'managed-assets\n'])
    with open('manifest.yaml', 'w') as f:
        f.writelines(['project:\n', '  dependencies:\n', '  repository:\n', '    - path: https://gop.isthatokay.com\n'])


def fake_request(repository, dependency):
    version = str(dependency["version"])
    path = str(repository["path"])
    assert re.match(VERSION_REGEX, version), "Invalid version numbering"
    assert re.match(PATH_REGEX, path)
    print("GET " + path + "/" + dependency["name"] + ":" + version)


def fake_post_request(manifest, payload):
    path = str(manifest["package"]["repository"][0]['path'])
    package_name = str(manifest["package"]["name"])
    version = str(manifest["package"]["version"])
    print("POST " + path + "/" + package_name + "/" + version)
    print(payload)


@cli.command('pull')
def pull():
    with open('test/test-manifest.yaml') as document:
        manifest = yaml.load(document, Loader=Loader)
        repository = manifest["project"]["repository"][0]
        dependencies = manifest["project"]["dependencies"]
        for dependency in dependencies:
            #TODO check pkg for current version
            fake_request(repository, dependency)


@cli.command('trust-key')
@click.option('--key', required=False)
@click.option('--key-file', type=click.Path(exists=True, readable=True, path_type=str), required=True)
@click.option('--author', required=True)
def trust(key, key_file, author):
    if key_file is not None:
        key = read_key_from_file(key_file)
    if key == key_file and key is None:
        print("Please supply either key or key file")
        exit(1)
    trust_dict = settings.get('trust-list', default={})
    try:
        # Validate key
        jwk.JWK.from_pem(key, 'utf-8')
        trust_dict[author] = key
        settings.save()
    except TypeError as e:
        print("Invalid key format, please use DER formatting")
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


def pack(directory, key, author):
    shutil.make_archive('package', 'zip', directory)
    b64 = b64_encode_file('package.zip')
    package_hash = hash_zip('package.zip')
    payload = {'package': str(b64, 'utf-8'), 'package_hash': package_hash, 'author': author}
    return sign_payload(payload, key)


def sign_payload(payload, pem):
    private_key = jwk.JWK.from_pem(pem)
    return jwt.generate_jwt(payload, private_key, 'RS256')


def parse_yaml(manifest):
    with open(manifest) as document:
        return yaml.load(document, Loader=Loader)


@cli.command('package')
@click.option('--key-file', type=click.Path(exists=True, readable=True, path_type=str), required=True)
def package(key_file):
    key = read_key_from_file(key_file)
    token = pack('./test', key, 'felixhellman')
    manifest = parse_yaml('./test/package-manifest.yaml')
    fake_post_request(manifest, token)
    pass


@cli.command('generate-key-pair')
def generate_key_pair():
    key = jwk.JWK.generate(kty='RSA', size=2048)
    priv_pem = key.export_to_pem(private_key=True, password=None)
    pub_pem = key.export_to_pem()
    with open('public-key.pem', 'wb') as f:
        f.write(pub_pem)
    with open('private-key.pem', 'wb') as f:
        f.write(priv_pem)
    settings.save()


if __name__ == '__main__':
    cli()
