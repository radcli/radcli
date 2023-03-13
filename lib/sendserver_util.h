#ifndef RC_SENDSERVER_UTIL_H
#define RC_SENDSERVER_UTIL_H

int rc_pack_list(VALUE_PAIR * vp, char *secret, AUTH_HDR * auth);
void strappend(char *dest, unsigned max_size, int *pos, const char *src);
int populate_ctx(RC_AAA_CTX ** ctx, char secret[MAX_SECRET_LENGTH + 1],
			uint8_t vector[AUTH_VECTOR_LEN]);
int rc_send_server(rc_handle * rh, SEND_DATA * data, char *msg, rc_type type);
int rc_check_reply(AUTH_HDR * auth, int bufferlen, char const *secret,
			  unsigned char const *vector, uint8_t seq_nbr);
void rc_random_vector(unsigned char *vector);
int add_msg_auth_attr(rc_handle * rh, char * secret, AUTH_HDR *auth, int total_length);


#endif
