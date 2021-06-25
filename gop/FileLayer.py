import base64
import yaml
import shutil
import os

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper


class FileLayer:
    def __init__(self):
        pass

    def b64_encode_file(self, path):
        with open(path, 'rb') as f:
            return str(base64.b64encode(f.read()), 'utf-8')

    def add_pkg(self, dependency, version):
        found = False
        with open('manifest.yaml') as document:
            manifest = yaml.load(document, Loader=Loader)
            if manifest['project']['dependencies'] is None:
                manifest['project']['dependencies'] = []
            for dep in manifest['project']['dependencies']:
                if dep['name'] in dependency:
                    found = True
            if not found:
                manifest['project']['dependencies'].append({"name": dependency, "version": version})
        if not found:
            with open('manifest.yaml', 'w') as f:
                yaml.dump(manifest, f)
        return not found

    def save_b64_pkg_zip(self, encoded_file):
        data = self.b64_decode_string(encoded_file)
        with open('pkg.zip', 'wb') as f:
            f.write(data)
        pass

    def b64_decode_string(self, value):
        return base64.b64decode(value)

    def unzip(self, dependency):
        split_name = dependency['name'].split('/')
        dep_name = split_name[0] + "-" + split_name[1]
        shutil.unpack_archive('pkg.zip', './tmp/' + dep_name)
        os.remove("pkg.zip")
        src = "./tmp/" + dep_name + "/" + split_name[1] + "-main" + "/pkg/" + dep_name
        dst = "./pkg/"
        shutil.move(src, dst)

    def load_dependency_manifest(self, dependency):
        split_name = dependency['name'].split('/')
        dep_name = split_name[0] + "-" + split_name[1]
        return self.parse_yaml("./tmp/" + dep_name + "/" + split_name[1] + "-main/manifest.yaml")

    def parse_yaml(self, manifest):
        with open(manifest) as document:
            return yaml.load(document, Loader=Loader)
