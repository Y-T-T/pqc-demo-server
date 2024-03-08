set(
    SOURCES
    rsa_pss_rsae_sha_t.c tls13_hkdf_expand.c
    )

add_library(tls ${SOURCES})