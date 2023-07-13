# InfinitEIDPQ-device-management

This project provides management console for ESP32 applet firmaware capable of communicating with [Web-eID](https://web-eid.eu/) solution.

## Project functionality

* initialize the device
    * create and upload certificates of device's public keys
    * requires root CA for creating anchor of trust of card's certificates
* handle PINs
    * auth
    * sign
    * admin
* handle individual APDU commands
* test Web-eID compatibility

## File structure description

* `bin/cli` = management console
* `bin/init` = initialization script
* `config` = contains config .yaml files
    * `constants.yaml` = constants used in the project
    * `config.yaml` = other configuration values
* `data` = contains PQ root self-signed certificate files 
    * `MAKECERT.md` = instructions how to create such PQ certificate files (requires [OQS-OpenSSL](https://github.com/open-quantum-safe/oqs-provider) provider installed)
* `tests` = constains unit tests, can be run by `pytest`
    * `test_web_eid_app_compatibility` = test whether connected device handles all operations required by Web-eID
* `infiniteidpq_device_manager` = source files for package installation
* `setup.py` = definition of package installation

## Usage

1. install package
   * `pip install <path-to-folder-containing-setup.py>`
2. (after fresh load of ESP32 applet firmware) initialize the device using first cli option (`python bin/cli.py` ) or by running `python bin/init.py`
3. (if applet already initialized) run other commands according to user's need
   * for example to unblock user's auth PIN, first verify admin PIN, then set auth PIN
4. (to test if card is working with Web-eID) run `pytest tests`
