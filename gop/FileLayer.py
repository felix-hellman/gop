import base64
import yaml
import shutil
import os
import hashlib


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

    def package_dependency(self, manifest):
        directory = self.format_pkg_path(manifest)
        shutil.make_archive('pkg', 'zip', directory)
        b64 = FileLayer().b64_encode_file('pkg.zip')
        package_hash = self.hash_zip('pkg.zip')
        os.remove('pkg.zip')
        return b64, package_hash

    def hash_zip(self, zipped_file):
        package_hash = hashlib.sha512()
        with open(zipped_file, 'rb') as f:
            package_hash.update(f.read())
        return package_hash.hexdigest()

    def load_dependency_manifest(self, dependency):
        split_name = dependency['name'].split('/')
        dep_name = split_name[0] + "-" + split_name[1]
        return self.parse_yaml("./tmp/" + dep_name + "/" + split_name[1] + "-main/manifest.yaml")

    def parse_yaml(self, manifest):
        with open(manifest) as document:
            return yaml.load(document, Loader=Loader)

    def unpack_dependency(self, package, manifest):
        dependencies = manifest["project"]["dependencies"]
        if dependencies is None:
            dependencies = []
        binary_data = self.b64_decode_string(package)
        os.makedirs(self.format_pkg_path(manifest), exist_ok=True)
        with open('pkg.zip', 'wb') as f:
            f.write(binary_data)
        shutil.unpack_archive('pkg.zip', self.format_pkg_path(manifest))
        os.remove('pkg.zip')
        return dependencies

    def format_pkg_path(self, manifest):
        author = manifest["project"]["package"]["author"]
        package_name = manifest["project"]["package"]["name"]
        return './pkg/' + author + "-" + package_name

    def load_base_url(self):
        return self.parse_yaml("./manifest.yaml")["project"]["repository"][0]["path"]