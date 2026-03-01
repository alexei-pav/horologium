#ifndef SK_FILESYSTEM_H
#define SK_FILESYSTEM_H

enum {
  final_code_len     = 6,
  msg_len            = 8,
  default_secret_len = 128
};

void save_secret(const char *path, const char *name, const char *secret);
int get_secret(const char *filename, const char *target_name,
	        char *out_secret, int secret_len);

#endif
