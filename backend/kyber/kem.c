#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
// #include "params.h"
// #include "kem.h"
#include <kyber/kem.h>
#include "indcpa.h"
#include "verify.h"
#include "symmetric.h"
#include "randombytes.h"

/*************************************************
* Name:        crypto_kem_keypair
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_keypair(uint8_t *pk,
                       uint8_t *sk)
{
  size_t i;
  indcpa_keypair(pk, sk);
  for(i=0;i<KYBER_INDCPA_PUBLICKEYBYTES;i++)
    sk[i+KYBER_INDCPA_SECRETKEYBYTES] = pk[i];
  hash_h(sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  /* Value z for pseudo-random output on reject */
  randombytes(sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES);

  //輸出公鑰

  // printf("\n\nPublic key (pk) :\n\n");
  // for(i=0; i<KYBER_PUBLICKEYBYTES; i++)
  //   printf("%02x ", pk[i]);
  // printf("\n\n\n\n");

  // 輸出私鑰

  // printf("Private key (sk) :\n\n");
  // for(i=0; i<KYBER_SECRETKEYBYTES; i++)
  //   printf("%02x ", sk[i]);
  // printf("\n\n\n\n");

  return 0;
}

/*************************************************
* Name:        crypto_kem_enc
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - uint8_t *ct: pointer to output cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_enc(uint8_t *ct,
                   uint8_t *ss,
                   const uint8_t *pk)
{
  size_t i;
  uint8_t buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];

  randombytes(buf, KYBER_SYMBYTES);
  /* Don't release system RNG output */
  hash_h(buf, buf, KYBER_SYMBYTES);

  /* Multitarget countermeasure for coins + contributory KEM */
  hash_h(buf+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(ct, buf, pk, kr+KYBER_SYMBYTES);

  /* overwrite coins in kr with H(c) */
  hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
  /* hash concatenation of pre-k and H(c) to k */
  kdf(ss, kr, 2*KYBER_SYMBYTES);

  // 輸出隨機對稱密鑰

  // printf("Session key (Shared secret) :\n\n");
  // for(i=0; i<KYBER_SSBYTES; i++)
  //   printf("%02x ", ss[i]);
  // printf("\n\n\n\n");

  // 輸出封裝後的密鑰

  // printf("Encapsulated key (Ciphertext) :\n\n");
  // for(i=0; i<KYBER_CIPHERTEXTBYTES; i++)
  //   printf("%02x ", ct[i]);
  // printf("\n\n\n\n");

  return 0;
}

/*************************************************
* Name:        crypto_kem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *ct: pointer to input cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - const uint8_t *sk: pointer to input private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*
* Returns 0.
*
* On failure, ss will contain a pseudo-random value.
**************************************************/
int crypto_kem_dec(uint8_t *ss,
                   const uint8_t *ct,
                   const uint8_t *sk)
{
  size_t i;
  int fail;
  uint8_t buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];
  uint8_t cmp[KYBER_CIPHERTEXTBYTES];
  const uint8_t *pk = sk+KYBER_INDCPA_SECRETKEYBYTES;

  indcpa_dec(buf, ct, sk);

  /* Multitarget countermeasure for coins + contributory KEM */
  for(i=0;i<KYBER_SYMBYTES;i++)
    buf[KYBER_SYMBYTES+i] = sk[KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES+i];
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(cmp, buf, pk, kr+KYBER_SYMBYTES);

  fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

  /* overwrite coins in kr with H(c) */
  hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);

  /* Overwrite pre-k with z on re-encryption failure */
  cmov(kr, sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES, fail);

  /* hash concatenation of pre-k and H(c) to k */
  kdf(ss, kr, 2*KYBER_SYMBYTES);

  // 輸出解封後的密鑰

  // printf("Session key (Shared secret) :\n\n");
  // for(i=0; i<KYBER_SSBYTES; i++)
  //   printf("%02x ", ss[i]);
  // printf("\n\n\n\n");

  return 0;
}


/*

int main() {
    uint8_t pk[KYBER_PUBLICKEYBYTES];
    uint8_t sk[KYBER_SECRETKEYBYTES];
    uint8_t ct[KYBER_CIPHERTEXTBYTES];
    uint8_t ss_enc[KYBER_SSBYTES], ss_dec[KYBER_SSBYTES];

    // 生成密鑰對
    crypto_kem_keypair(pk, sk);
    printf("Key pair generated.\n\n\n\n\n\n\n\n");

    // 封裝
    crypto_kem_enc(ct, ss_enc, pk);
    printf("Key encapsulated.\n\n\n\n\n\n\n\n");

    // 解封
    crypto_kem_dec(ss_dec, ct, sk);
    printf("Key decapsulated.\n\n\n\n\n\n\n\n");

    // 檢查共享金鑰是否相同
    int is_equal = 1;
    for (int i = 0; i < KYBER_SSBYTES; i++) {
        if (ss_enc[i] != ss_dec[i]) {
            is_equal = 0;
            break;
        }
    }

    if (is_equal) {
        printf("Key encapsulation and decapsulation successful. Shared secrets match.\n\n\n");
    } else {
        printf("Mismatch in shared secrets. There might be an error.\n\n\n");
    }

    return 0;
}

*/
