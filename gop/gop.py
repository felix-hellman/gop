#! /usr/bin/python3

import click
import os
from easysettings import EasySettings
from gop import ApiClient
from gop import FileLayer
from gop import GopController

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


def create_api_client(fileLayer):
    if os.path.exists("./manifest.yaml"):
        url = fileLayer.parse_yaml("./manifest.yaml")["project"]["repository"][0]["path"]
        return ApiClient(settings.get("token"), url)
    return ApiClient(settings.get("token"), "")


def controller():
    fileLayer = FileLayer()
    return GopController(create_api_client(fileLayer), fileLayer)


@cli.command('init')
@click.option("--name", required=False)
@click.option('--author', required=False)
@click.option('--version', required=False)
def init_project(name, author, version):
    controller().init_project(name, author, version)


@cli.command('ping')
def ping():
    controller().ping()


@cli.command('upload-key')
@click.option('--key-file', type=click.Path(exists=True, readable=True, path_type=str), required=True)
def upload_key(key_file):
    controller().upload_key(key_file)


@cli.command('add')
@click.option('--dependency', required=True)
@click.option('--version', required=True)
def add_pkg(dependency, version):
    controller().add_pkg(dependency, version)


@cli.command('search')
@click.option('--author', required=True)
def search(author):
    controller().search(author)


@cli.command('update')
@click.option('--dry-run', required=False, count=True)
def update(dry_run):
    controller().update(dry_run)


@cli.command('login')
@click.option('--token', required=False)
@click.option('--repo', required=False, count=True)
def login(token, repo):
    controller().login(token, repo)


@cli.command('logout')
def logout():
    controller().logout()


@cli.command('install')
def install():
    controller().install()


@cli.command('trust-key')
@click.option('--key-file', type=click.Path(exists=True, readable=True, path_type=str), required=True)
def trust(key_file, author):
    controller().trust(key_file, author)


@cli.command('package')
@click.option('--key-file', type=click.Path(exists=True, readable=True, path_type=str), required=True)
def package(key_file):
    controller().package(key_file)


@cli.command('generate-key-pair')
def generate_key_pair():
    controller().generate_key_pair()


if __name__ == '__main__':
    cli()


def __main__():
    cli()
