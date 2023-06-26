# Connector

This project provides management console for JavaCard applet capable of communicating with [Web-eID](https://web-eid.eu/) solution.

## Project functionality

* initialize the device
    * create and upload certificates of device's public keys
    * requires root CA for creating anchor of trust of device's certificates
* handle PINs
    * auth
    * sign
    * admin
* handle individual APDU commands
* test Web-eID compatibility

## File structure description

* `bin/cli` = management console
* `config` = contains config .yaml files
    * `apdulist.yaml` = definitions of necessary APDUs
    * `config.yaml` = other configuration values
* `data` = contains root self-signed certificate files
    * `MAKECERT.md` = instructions how to create such certificate files
* `tests` = constains unit tests, can be run by `pytest`
    * `test_web_eid_app_compatibility` = test whether connected device handles all operations required by Web-eID
* `src` = source files for package installation
* `setup.py` = definition of package installation

## Dependencies

You will need to install OpenSSL command-line utility with post-quantum algorithms enabled.
For OpenSSL v1.1.1, follow install instructions at: <https://github.com/open-quantum-safe/openssl>
For OpenSSL v3, here is more detailed guide:

1. `git clone https://github.com/open-quantum-safe/oqs-provider.git && cd oqs-provider`
1. `OPENSSL_INSTALL=/opt/homebrew/opt/openssl@3` (or wherever you have OpenSSL v3 installed)
1. `./script/fullbuild.sh -F`
1. `cp _build/lib/oqsprovider.* /opt/homebrew/opt/openssl@3/lib/ossl-modules/` (or wherever you have OpenSSL v3 installed)
1. locate active `openssl.cnf`
   * most probably in directory from `openssl version -d`
   * in case of homebrew on MacOS, it is at `/opt/homebrew/etc/openssl@3/openssl.cnf`
1. activate `default` and `oqsprovider` like this:

    ```
    [openssl_init]
    providers = provider_sect

    # List of providers to load
    [provider_sect]
    default = default_sect
    oqsprovider = oqsprovider_sect
    legacy = legacy_sec

    [default_sect]
    activate = 1
    [oqsprovider_sect]
    activate = 1
    [legacy_sect]
    #activate = 1
    ```

1. verify that you can use `openssl` with post-quantum algorithms: `openssl list -signature-algorithms`

## Usage

1. install package
   * `pip install <path-to-folder-containing-setup.py>`
1. run console
   * `python bin/cli`
1. (after fresh load of JavaCard applet) initialize the device using first cli option
1. (if applet already initialized) run other commands according to user's need
   * for example to unblock user's auth PIN, first verify admin PIN, then set auth PIN
1. (to test if device is working with Web-eID) run `pytest tests` (`-s` for printing APDU commands used)
