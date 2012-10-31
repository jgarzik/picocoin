#ifndef __LIBTEST_H__
#define __LIBTEST_H__

#include <jansson.h>

extern json_t *read_json(const char *filename);
extern char *test_filename(const char *basename);

#endif /* __LIBTEST_H__ */
