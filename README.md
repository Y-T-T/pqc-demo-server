## PQC demo server

### intro

This is a proxy server demonstration based on TLS 1.3 hybrid post-quantum encryption protocol encryption:`X25519Kyber768Draft00`

`X25519Kyber768Draft00` definition: https://www.ietf.org/archive/id/draft-tls-westerbaan-xyber768d00-02.html

### requirement

* `Python >= 3.10.12`
* `cmake >= 3.12`
* `openssl >= 3.0.2`
* `npm >= 10.2.4`

### framework

* Backend: `flask`
* Proxy: `c`
* Frontend: `reactJS`

## Platform Support

![Linux](https://img.shields.io/badge/platform-Linux-green.svg)
![macOS](https://img.shields.io/badge/platform-macOS-green.svg)

This software is optimized for **Linux** and **macOS** platforms.

### setup

1. Package the server certificate in the `cert` folder, and then copy the entire `cert` folder to the `src` folder
2. run `setup` script (Use `sudo` if necessary)