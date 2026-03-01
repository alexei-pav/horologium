#include "filesystem.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>

/* ========== SAVE SECRETS ========== */

static void write_file(int fd, const char *s)
{
  int len, written;
  if(!s) {
    fprintf(stderr, "write_file: string is NULL\n");
    return;
  }

  len = strlen(s);
  written = 0;
  while(written < len) {
    int res;

    res = write(fd, s + written, len - written);
    if(res < 0) {
      perror("write");
      return;
    }
    written += res;
  }
}

void
save_secret(const char *path, const char *name, const char *secret)
{
  int fd, res;

  fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
  if(fd == -1) {
    fprintf(stderr, "Error while creating file\n");
    exit(0);
  }

  /* write name*/
  write_file(fd, name);

  res = write(fd, " ", 1);
  if(res != 1) {
    perror("write space");
    close(fd);
    exit(1);
  }

  /* write secret */
  write_file(fd, secret);

  res = write(fd, "\n", 1);
  if(res != 1) {
    perror("write newline");
    close(fd);
    exit(1);
  }
  close(fd);
}

/* ========== GET SECRET ========== */

int
get_secret(const char *filename, const char *target_name,
            char *out_secret, int secret_len)
{
  FILE *f;
  int c, res;
  char name[128];
  char secret[default_secret_len+1];

  /* open the file */
  f = fopen(filename, "r");
  if (!f) return 0;

  int npos = 0;      /* position in name */
  int spos = 0;      /* position in secret */
  int read_name = 1; /* 1 = reading name; 0 = reading secret */

  while ((c = fgetc(f)) != EOF) {
    /* end of line */
    if (c == '\n') {
      name[npos] = '\0';
      secret[spos] = '\0';
      
      /* compare the name with the target */
      res = strcmp(name, target_name);
      if (res == 0) {
        /* ensure null-termination and copy the secret */
        strncpy(out_secret, secret, secret_len);
        out_secret[secret_len] = '\0';
        fclose(f);
        return 1;
      }

      /* reset for the next line */
      npos = 0;
      spos = 0;
      read_name = 1;
      continue;
    }

    /* first space means we're going to read the secret */
    if (read_name && c == ' ') {
      read_name = 0;
      continue;
    }

    /* write symbols to name or secret */
     if (read_name) {
      if (npos < sizeof(name) - 1) {
        name[npos] = (char)c;
        npos++;
      }
    } else {
      if (spos < sizeof(secret) - 1) {
        secret[spos] = (char)c;
        spos++;
      }
    }
  }

  /* handle the last line in case it doesn't end with a newline */
  if (npos > 0 || spos > 0) {
    name[npos] = '\0';
    secret[spos] = '\0';
    res = strcmp(name, target_name);
    if (res == 0) {
      strncpy(out_secret, secret, secret_len - 1);
      out_secret[secret_len - 1] = '\0';
      fclose(f);
      return 1;
    }
  }
  
  fclose(f);
  return 0;
}
