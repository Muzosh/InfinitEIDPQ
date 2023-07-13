# InfinitEIDPQ

This repository contains Arduino-ESP32 applet firmware designed to work with https://github.com/Muzosh/Post-Quantum-Authentication-On-The-Web project. It implements post-quantum algorithms (currently Dilithium5 and Falcon1024) and operates to the similar way as smart card does: it listens for pre-defined APDU commands and sends back responses via USB serial port.

Repository consists of three sub-projects (please read corresponding `README.md` in each sub-project):

1. `InfinitEIDPQ-applet` - ESP32 applet firmware source code and build files + instructions
2. `InfinitEIDPQ-device-management` - Python management console (device initialization and management)
3. `pkcs11` - a PKCS#11 interface implementation for this device (unfinished)

## Simplified Usage

See individual nested READMEs for more details. First, build and flash the applet to ESP32. Then, initialize it using the InfinitEIDPQ-device-management. Finally, you can include the PKCS#11 interface in your project and use it to communicate with the device (or hard-code it into the application as it was done in https://github.com/Muzosh/Post-Quantum-Authentication-On-The-Web project).