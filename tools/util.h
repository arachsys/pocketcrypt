#ifndef UTIL_H
#define UTIL_H

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

extern int getentropy(void *data, size_t length);

static const int in = STDIN_FILENO, out = STDOUT_FILENO;
static const size_t chunk = 1 << 20;

static inline size_t get(int fd, uint8_t *data, size_t length) {
  ssize_t count, total = 0;
  while (length && (count = read(fd, data, length))) {
    if (count >= 0)
      data += count, length -= count, total += count;
    else if (errno != EINTR && errno != EAGAIN)
      err(EXIT_FAILURE, "read");
  }
  return (size_t) total;
}

static inline void load(const char *file, void *data, size_t length) {
  int fd = file ? open(file, O_RDONLY) : in;
  if (file && fd < 0)
    err(EXIT_FAILURE, "%s", file);
  if (get(fd, data, length) != length)
    errx(EXIT_FAILURE, "%s is truncated", file);
  if (file)
    close(fd);
}

static inline void put(int fd, const uint8_t *data, size_t length) {
  while (length > 0) {
    ssize_t count = write(fd, data, length);
    if (count >= 0)
      data += count, length -= count;
    else if (errno != EINTR && errno != EAGAIN)
      err(EXIT_FAILURE, "write");
  }
}

static inline void randomise(void *data, size_t length) {
  if (getentropy(data, length))
    err(EXIT_FAILURE, "getentropy");
}

static inline void save(const char *file, const void *data,
    size_t length) {
  int fd = file ? open(file, O_WRONLY | O_CREAT | O_TRUNC, 0600) : out;
  if (file && fd < 0)
    err(EXIT_FAILURE, "%s", file);
  put(fd, data, length);
  if (file)
    close(fd);
}

#endif
