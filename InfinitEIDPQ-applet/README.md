# InfinitEIDPQ-applet

This project provides ESP32 applet firmware capable of communicating with [Web-eID](https://web-eid.eu/) solution. It implements post-quantum algorithms (currently Dilithium5 and Falcon1024) and operates to the similar way as smart card does: it listens for pre-defined APDU commands and sends back responses via USB serial port.

> Web-eID app needs to be tweaked in order to accept InfinitEIDPQ: <https://github.com/Muzosh/web-eid-app/tree/feature-abstraction-layer-and-serial-devices>

## Applet functionality

* two keypairs
    * for authentication
    * for digital signature
* two certificates for public keys
* currently Dilithium5 and Falcon1024 are implemented
* auth, sign and admin PIN
    * maximum PIN size
    * maximum retries + block/unblock
    * changing PIN
* reading and writing binary data (currently used for certificates)
* security - **USE AT YOUR OWN RISK**:
    * on-device encryption of PIN values, PIN states and private keys by using assymetric key derived from PIN value
    * migration to a device with integrated HSM/TPM module is planned

## Usage

Current usage is specific to my development device, which was LilyGO T-display S3

1. download `PlaftormIO` extension for VSCode
2. in the left sidebar, click on `PlatformIO` icon and choose `Pick a folder`
3. choose `InfinitEIDPQ-applet` folder
4. run `PlatformIO: Pick Project Environment` command and choose `env:tdisplay`
5. run `PlatformIO: Build` command
6. connect device to the computer via USB
7. try to run `Tasks: Run Task` command and choose `PlatformIO: erase flash (tdisplay)`
   * you might need choose `Show All Tasks` first
   * you might need to put the device into BOOT mode, which is device-specific - for LilyGO T-display S3, you need to hold `BOOT` button and then press `RST` button
8. try to run `PlatformIO: Upload` command
   * you might need to put the device into BOOT mode, which is device-specific - for LilyGO T-display S3, you need to hold `BOOT` button and then press `RST` button
9. after successful upload, device is ready to be initialized, go to the parent repository and follow steps in the `InfinitEIDPQ-device-management` README.md
