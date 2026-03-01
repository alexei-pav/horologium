#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>

#include "hmac.h"
#include "filesystem.h"

#define DEFAULT_SECRET "ABCDEFGHIJKLMNOPQ"
#define DEFAULT_NAME "test"
#define DB_FILE ".totp_db"

/* ========== HELP ========== */

static void print_version()
{
  fputs("Safekey v0.1.0-beta\n", stdout);
}

static const char helptxt[] = {
  "\n"
  "Warning: IT IS A BETA VERSION, CONTAINS BUGS AND ERRORS\n"
  "\n"
  "Usage: safekey [OPTIONS] [BASE32_SECRET]\n"
  "If no secret specified, default is: " DEFAULT_SECRET "\n"
  "\n"
  "With no OPTIONS generates TOTP using provided secret. "
  "If no secret provided DEFAULT_SECRET is used.\n"
  "\n"
  "OPTIONS:\n" 
  "\t-a   add new	secret in database\n"
  "\t-l   load secret by name and	generate TOTP with it\n"
  "\t-v   enable verbose output\n"
  "\t-q   quiet, disables any verbose output at all\n"
  "\t-h   display this help and exit\n"
  "\n"
  "Examples:\n"
  "\tsafekey -a " DEFAULT_NAME DEFAULT_SECRET "   " 
  "Save secret '" DEFAULT_SECRET "' with name '" DEFAULT_NAME "' to database\n"
  "\tsafekey -l " DEFAULT_NAME "   Load secret with name '" DEFAULT_NAME "'\n"
};

static void print_help()
{
  print_version();
  fputs(helptxt, stdout);
}


/* ========== BASE32 DECODER ========== */

static int base32_val(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= '2' && c <= '7') return c - '2' + 26;
  return -1;
}

static int base32_decode(const char *in, unsigned char *out, int *out_len) {
  int len;
  int buffer = 0, bits = 0, idx = 0;

  len = strlen(in);

  int i;
  for (i = 0; i < len; i++) {
    int v; 
    v = base32_val(in[i]);
    if (v < 0) continue; /* ignore padding and invalid chars */

    buffer = (buffer << 5) | v;
    bits += 5;

    if (bits >= 8) {
      bits -= 8;
      out[idx] = (buffer >> bits) & 0xFF;
      idx++;
    }
  }

  *out_len = idx;
  return 0;
}


/* ========== TOTP ========== */

unsigned int totp(const unsigned char *key,
	          int key_len,
	          unsigned long step,
	          int digits) {
  unsigned char msg[8], hash[20];
  int offset;
  unsigned int code, res;

  int i;
  for (i = 7; i >= 0; i--) {
    msg[i] = step & 0xFF;
    step >>= 8;
  }
  hmac_sha1(key, key_len, msg, msg_len, hash);

  offset = hash[19] & 0x0F;

  code = (hash[offset] & 0x7F)   << 24 |
         (hash[offset+1] & 0xFF) << 16 |
         (hash[offset+2] & 0xFF) << 8  |
         (hash[offset+3] & 0xFF);

  unsigned int mod = 1;
  for (i = 0; i < digits; i++) mod *= 10;
  
  res = code % mod;
  return res;
}


/* ========== CLI PARSE ==========*/

struct cmdline_opts {
    int verbosity;
    int help;
    int save_secret;
    int load_secret;
    const char *base32_secret;
    const char *name;
};

static void set_defaults(struct cmdline_opts *opts)
{
    opts->verbosity     = 0;
    opts->help          = 0;
    opts->save_secret   = 0;
    opts->load_secret   = 0;
    opts->base32_secret = DEFAULT_SECRET;
    opts->name          = DEFAULT_NAME;
}

static int 
parse_cmdline(int argc, const char **argv, struct cmdline_opts *opts)
{
  int idx = 1;
  while(idx < argc) {
    if(argv[idx][0] == '-') {
      switch(argv[idx][1]) {
        case 'v':
          opts->verbosity++;
          idx++;
          break;
        case 'q':
          opts->verbosity = -1;
          idx++;
          break;
        case 'h':
          opts->help = 1;
          idx++;
          break;
	case 'a':
	  if(idx < argc && argv[idx+1] && argv[idx+1][0] != '-') {
            opts->save_secret = 1;
	    opts->name = argv[idx+1];
	    idx += 2;
	  } /* TODO: add an error if no name provided*/
	  break;
	case 'l':
	  if(idx < argc && argv[idx+1] && argv[idx+1][0] != '-') {
	    opts->load_secret = 1;
	    opts->name = argv[idx+1];
	    idx += 2;
	  } /* TODO: same as for case 'a' */
	  break;
        default:
          fprintf(stderr, "unknown option ``-%c''\n", argv[idx][1]);
          return 0;
      }
    } else {
      opts->base32_secret = argv[idx];
      return 1;
    }
  }
  return 1;
}


/* ========== MAIN ========== */

int main(int argc, const char **argv)
{
  struct cmdline_opts opts;

  unsigned char key[64];
  char secret[default_secret_len+1]; /* adding one for null-terminator*/
  unsigned long now, step;
  unsigned int code;
  int res;

  /* get the home dir */
  char db_path[512];
  const char* home = getenv("HOME");
  if (home == NULL) {
   fprintf(stderr, "HOME environment variable is not set.\n");
   return 1;
  }
  snprintf(db_path, sizeof(db_path), "%s%c%s", home, '/', DB_FILE);

  set_defaults(&opts);
  res = parse_cmdline(argc, argv, &opts);
  if(!res) {
    printf("Error: wrong parameter");
    return -1;
  }
  if(opts.help) {
    print_help();
    return 0;
  } 
  
  if(opts.save_secret && opts.load_secret) { 
    fprintf(stderr, "Error: -l and "
		  "-a options are conflicting, don't use them in same time"); 
    return 1;
  } else if(opts.save_secret) {
    save_secret(db_path, opts.name, opts.base32_secret);
    return 0;
  } else if(opts.load_secret) {
    res = get_secret(db_path, opts.name, secret, default_secret_len);
    if(!res) {
      fprintf(stderr, "Error: secret not found for %s\n", opts.name);
      return 1;
    }
    opts.base32_secret = secret;
  }

  int key_len = 0;
  base32_decode(opts.base32_secret, key, &key_len);

  now = time(NULL);
  step = now / 30;

  code = totp(key, key_len, step, final_code_len);

  printf("%06u\n", code);
  return 0;
}

