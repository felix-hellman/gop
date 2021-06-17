from setuptools import setup

reqs = []
with open('requirements.txt', 'r') as f:
    for line in f.readlines():
        print(line)
        reqs.append(line)

setup(
    name='gop',
    version='0.0.4',
    packages=['gop'],
    url='https://gop.shrimpray.com',
    license='MIT License',
    author='Wheely',
    author_email='felixhellman.ro@gmail.com',
    description='Package manager for godot',
    install_requires=reqs,
    entry_points={
        'console_scripts': ['gop=gop.gop:__main__']
    }
)
