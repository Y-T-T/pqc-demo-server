![Linux](https://img.shields.io/badge/platform-Linux-green.svg)
![macOS](https://img.shields.io/badge/platform-macOS-green.svg)
![X25519Kyber768Draft00](https://img.shields.io/badge/TLS-X25519Kyber768Draft00-88292f)

## PQC demo server

### Intro

This is a [proxy server](https://www.pqc-demo.xyz) demonstration based on TLS 1.3 hybrid post-quantum encryption protocol encryption:`X25519Kyber768Draft00`

`X25519Kyber768Draft00` definition: https://www.ietf.org/archive/id/draft-tls-westerbaan-xyber768d00-02.html

### Requirement

* ![python](https://img.shields.io/badge/python-3.10.12-blue)
* ![gunicorn](https://img.shields.io/badge/gunicorn-21.2.0-blue)
* ![cmake](https://img.shields.io/badge/cmake-3.12-blue)
* ![openssl](https://img.shields.io/badge/openssl-3.0.2-blue)
* ![npm](https://img.shields.io/badge/npm-10.2.4-blue)
* ![chrome](https://img.shields.io/badge/chrome-116-blue)

### Framework

* ![backend](https://img.shields.io/badge/backend-flask-689689)
* ![proxy](https://img.shields.io/badge/proxy-C-689689)
* ![frontend](https://img.shields.io/badge/frontend-reactJS-689689)

### Setup

#### Server
1. Put the server certificate in the `cert` folder, and then copy the entire `cert` folder to the `backend/src` folder
2. Put the file names of the certificate and key into `backend/setting.conf`
3. run `setup` script (Use `sudo` if necessary)

#### Client
1. Open the chrome and goto `chrome://flags`
2. Enable `TLS 1.3 hybridized Kyber support`


#### Notice
* The cert folder must contain the X.509 certificate in `DER` format and the key in `PEM` format.
* The gunicron server logs will be output to `backend/access.log` and `backend/error.log`