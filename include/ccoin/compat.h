#ifndef __LIBCCOIN_COMPAT_H__
#define __LIBCCOIN_COMPAT_H__

/* NOTE: this file requires, but does not include, picocoin-config.h */

/* TODO: this stuff probably should be hidden, not exported
 * alongside all the other API headers
 */

#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HAVE_FDATASYNC
static inline int fdatasync(int fd)
{
#ifdef WIN32
	return _commit(fd);
#else
	return fsync(fd);
#endif
}
#endif /* !HAVE_FDATASYNC */

#ifndef HAVE_MEMMEM
extern void *memmem(const void *haystack, size_t haystacklen,
                    const void *needle, size_t needlelen);
#endif /* !HAVE_MEMMEM */

#ifndef HAVE_MKSTEMP
#define mkstemp(tmpl) g_mkstemp(tmpl)
#endif /* !HAVE_MKSTEMP */

#ifndef HAVE_STRNDUP
#define strndup(s,n) g_strndup(s,n)
#endif /* !HAVE_STRNDUP */

#ifdef __cplusplus
}
#endif

#endif /* __LIBCCOIN_COMPAT_H__ */
