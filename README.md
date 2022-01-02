# bn-kconfig-recover ![Python Lint](https://github.com/zznop/bn-kconfig-recover/workflows/pylint/badge.svg)

![demo bn-kconfig-recover](bn-kconfig-recover.gif)

## Description

Binary Ninja plugin that analyzes Linux kernel binaries to automate recovery of the build configuration (`.config`)

## Usage

```
usage: bn_kconfig_recover.py [-h] [-d] bndb kconfig

positional arguments:
  bndb         File path to kernel ELF or Binary Ninja database
  kconfig      File path to save recovered kernel configuration

optional arguments:
  -h, --help   show this help message and exit
  -d, --debug  Enable debug logging
```


