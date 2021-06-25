import base64
import yaml

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
