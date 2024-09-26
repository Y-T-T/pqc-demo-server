![Linux](https://img.shields.io/badge/platform-Linux-green.svg)
![macOS](https://img.shields.io/badge/platform-macOS-green.svg)
![X25519Kyber768Draft00](https://img.shields.io/badge/TLS-X25519Kyber768Draft00-88292f)

## PQC demo server

### Intro

This is a [proxy server](https://www.pqc-demo.xyz) demonstration based on TLS 1.3 hybrid post-quantum encryption protocol encryption:`X25519Kyber768Draft00`

`X25519Kyber768Draft00` definition: https://bwesterb.github.io/draft-westerbaan-tls-xyber768d00/draft-tls-westerbaan-xyber768d00.html

### Requirement

* ![python](https://img.shields.io/badge/python-3.10.12-blue)
* ![gunicorn](https://img.shields.io/badge/gunicorn-21.2.0-blue)
* ![cmake](https://img.shields.io/badge/cmake-3.12-blue)
* ![openssl](https://img.shields.io/badge/openssl-3.0.2-blue)
* ![nodeJS](https://img.shields.io/badge/nodeJS-22.7.0-blue)
* ![npm](https://img.shields.io/badge/npm-10.2.4-blue)
* ![chrome](https://img.shields.io/badge/chrome-%3E116-blue)

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
P.S. Chrome's default setting is now on


#### Notice
* The cert folder must contain the X.509 certificate in `DER` format and the key in `PEM` format.
* The gunicron server logs will be output to `backend/access.log` and `backend/error.log`

#### Warning
The new NIST standard ML-KEM has been released ([FIPS 203](https://doi.org/10.6028/NIST.FIPS.203)).
Chrome is expected to stop supporting the old version of Kyber in version 131, and this [update](https://security.googleblog.com/2024/09/a-new-path-for-kyber-on-web.html) is expected to be in November 2024.