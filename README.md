# Gop

## What is gop?

Gop is a package manager for godot.

## Installating Gop
```bash
pip3 install git+https://github.com/felix-hellman/gop.git --user
```

## Installing Public Packages

Installing packages with gop is pretty simple and requires no log in.

```bash
gop init
gop add --dependency=felix-hellman/awesome --version=0.0.1
gop install
```

## Installing Private Packages
Please see the wiki entry on [Packages](https://github.com/felix-hellman/gop/wiki/Packages)

## Features
* Public Repositories
  * Transitive Dependency Resolution
  * Package verification using PKI (RSA)
  * Version control
* Private Non-Versioned Github Backed Dependencies
  * Transitive Dependency Resolution

### Example projects
Usage of Genetic Algorithm - https://github.com/felix-hellman/gop-example-genetics
