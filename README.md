![Linux](https://img.shields.io/badge/platform-Linux-green.svg)
![macOS](https://img.shields.io/badge/platform-macOS-green.svg)
![X25519MLKEM768](https://img.shields.io/badge/TLS-X25519MLKEM768-88292f)
![TLS_AES_256_GCM_SHA384](https://img.shields.io/badge/Cipher-AES__256__GCM__SHA384-88292f)
![TLS_CHACHA20_POLY1305_SHA256](https://img.shields.io/badge/Cipher-CHACHA20__POLY1305__SHA256-88292f)

## PQC demo server

### Intro

This branch (`mlkem-dev`) contains updates and migration to the new ML-KEM (FIPS 203) standard for post-quantum hybrid ECDHE-MLKEM key agreement:`X25519MLKEM768`

`X25519MLKEM768` definition: https://www.ietf.org/archive/id/draft-kwiatkowski-tls-ecdhe-mlkem-02.html

### Requirement

* ![python](https://img.shields.io/badge/python-3.10.12-blue)
* ![gunicorn](https://img.shields.io/badge/gunicorn-21.2.0-blue)
* ![cmake](https://img.shields.io/badge/cmake-3.12-blue)
* ![openssl](https://img.shields.io/badge/openssl-3.0.2-blue)
* ![nodeJS](https://img.shields.io/badge/nodeJS-22.7.0-blue)
* ![npm](https://img.shields.io/badge/npm-10.2.4-blue)
* ![chrome](https://img.shields.io/badge/chrome-%3E131-blue)

### Framework

* ![backend](https://img.shields.io/badge/backend-flask-689689)
* ![proxy](https://img.shields.io/badge/proxy-C-689689)
* ![frontend](https://img.shields.io/badge/frontend-reactJS-689689)

### Setup

#### Server
**The self-signed SSL certificate for testing has been uploaded. If you do not have your own certificate, you can skip steps 1 and 2.**
1. Put the server certificate in the `cert` folder, and then copy the entire `cert` folder to the `backend/src` folder
2. Put the file names of the certificate and key into `backend/setting.conf`
3. run `setup` script (Use `sudo` if necessary)

#### Client
1. Open the chrome and go to `https://127.0.0.1`

#### Notice
* The cert folder must contain the X.509 certificate in `DER` format and the key in `PEM` format.
* The gunicron server logs will be output to `backend/access.log` and `backend/error.log`

### Acknowledgements
This project makes use of the following open-source projects:
- [mlkem-native](https://github.com/pq-code-package/mlkem-native)
