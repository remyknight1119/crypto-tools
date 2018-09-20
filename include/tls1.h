#ifndef __CT_TLS1_H__
#define __CT_TLS1_H__


extern int tls1_2_handshake_proc(ssl_conn_t *conn, void *data,
            uint16_t len, int client);
extern int tls1_2_application_data_proc(ssl_conn_t *conn, void *data,
            uint16_t len, int lcient);
extern int tls1_2_alert_proc(ssl_conn_t *conn, void *data, uint16_t len,
            int lcient);
extern int tls1_2_change_cipher_spec_proc(ssl_conn_t *conn, void *data,
            uint16_t len, int lcient);

#endif
