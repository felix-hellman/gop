# Gop

## What is gop?

Gop is a package manager for godot.
Currently only public packages are supported.

## How to use

### I want to install packages

Installing packages with gop is pretty simple and requires no log in.

```bash
gop init
gop add --dependency=felix-hellman/aweosme --version=0.0.1
gop install
```

### I want to deploy packages

To deploy packages you need the following
* A github account
* A private/public RSA key pair in pem format
* A package description in form of a yaml file

#### Startup

To effectivly create a new account with gop you can do the following
```bash
gop login
gop generate-key-pair #Skip this step if you want to provide your own keys
gop upload-key --key-file=path/to/public/key
```

You need to provide a public key so that the server can validate your signature when you upload packages

#### Deploying
Create a manifest.yaml file similar to this
```yaml
project:
  package: #This is the package we want to upload
    name: awesome
    author: felix-hellman
    version: 0.0.1
  dependencies: # This is a list of the dependencies that the package depends upon
  repository:
    - path: https://gop.shrimpray.com 
```

This structure can also be generated with
```
gop init --name=awesome --author=felix-hellman --version=0.0.1
```

To upload your package
```bash
gop package --key-file=path/to/private/key
```
Your private key is used for signing the package payload so that it can be verified on the server with the corresponding public key you uploaded
