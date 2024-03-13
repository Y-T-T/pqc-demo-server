set(
    SOURCES

    handshake.c
    rsa_pss_rsae_sha_t.c
    tls13_enc_dec.c
    tls13_hkdf_expand.c
    )

add_library(tls ${SOURCES})