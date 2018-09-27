#ifndef __CT_TLS1_H__
#define __CT_TLS1_H__

#define SSL_kRSA                        0x00000001U
#define SSL_kDHE                        0x00000002U
#define SSL_kECDHE                      0x00000004U

#define SSL_aRSA                        0x00000001U
#define SSL_aECDSA                      0x00000008U

#define SSL_DES                     0x00000001U
#define SSL_3DES                    0x00000002U
#define SSL_RC4                     0x00000004U
#define SSL_RC2                     0x00000008U
#define SSL_IDEA                    0x00000010U
#define SSL_eNULL                   0x00000020U
#define SSL_AES128                  0x00000040U
#define SSL_AES256                  0x00000080U
#define SSL_CAMELLIA128             0x00000100U
#define SSL_CAMELLIA256             0x00000200U
#define SSL_eGOST2814789CNT         0x00000400U
#define SSL_SEED                    0x00000800U
#define SSL_AES128GCM               0x00001000U
#define SSL_AES256GCM               0x00002000U
#define SSL_AES128CCM               0x00004000U
#define SSL_AES256CCM               0x00008000U
#define SSL_AES128CCM8              0x00010000U
#define SSL_AES256CCM8              0x00020000U

#define SSL_AESGCM                  (SSL_AES128GCM | SSL_AES256GCM)
#define SSL_AESCCM                  (SSL_AES128CCM | SSL_AES256CCM | SSL_AES128CCM8 | SSL_AES256CCM8)
#define SSL_AES                     (SSL_AES128|SSL_AES256|SSL_AESGCM|SSL_AESCCM)
#define SSL_CAMELLIA                (SSL_CAMELLIA128|SSL_CAMELLIA256)
#define SSL_CHACHA20                (SSL_CHACHA20POLY1305)

/* Bits for algorithm_mac (symmetric authentication) */

#define SSL_MD5                     0x00000001U
#define SSL_SHA1                    0x00000002U
#define SSL_GOST94                  0x00000004U
#define SSL_GOST89MAC               0x00000008U
#define SSL_SHA256                  0x00000010U
#define SSL_SHA384                  0x00000020U
#define SSL_AEAD                    0x00000040U
#define SSL_GOST12_256              0x00000080U
#define SSL_GOST89MAC12             0x00000100U
#define SSL_GOST12_512              0x00000200U

enum {
    TLS1_CHANGE_CIPHER_SPEC_TYPE_CHANGE_CIPHER_SPEC = 1,
    TLS1_CHANGE_CIPHER_SPEC_TYPE_MAX = 255,
};


extern int tls1_2_handshake_proc(ssl_conn_t *conn, void *data,
            uint16_t len, int client);
extern int tls1_2_application_data_proc(ssl_conn_t *conn, void *data,
            uint16_t len, int lcient);
extern int tls1_2_alert_proc(ssl_conn_t *conn, void *data, uint16_t len,
            int lcient);
extern int tls1_2_change_cipher_spec_proc(ssl_conn_t *conn, void *data,
            uint16_t len, int lcient);
extern int tls1_enc(ssl_conn_t *ssl, unsigned char *out,
            const unsigned char *in, uint32_t len);

#endif
