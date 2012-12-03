#ifndef __LIBCCOIN_COMPAT_H__
#define __LIBCCOIN_COMPAT_H__

/* NOTE: this file requires, but does not include, picocoin-config.h */

/* TODO: this stuff probably should be hidden, not exported
 * alongside all the other API headers
 */

#include <unistd.h>
#include <glib.h>

#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION < 30))
static inline GPtrArray *
g_ptr_array_new_full (guint          reserved_size,
                      GDestroyNotify element_free_func)
{
  GPtrArray *array;

  array = g_ptr_array_sized_new (reserved_size);
  g_ptr_array_set_free_func (array, element_free_func);
  return array;
}

static inline void
g_list_free_full(GList *element_list,
		      GDestroyNotify free_func)
{
  g_list_foreach(element_list, (GFunc)free_func, NULL);
  g_list_free(element_list);
}
#endif /* GLIB_VERSION < 2.30 */

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

#endif /* __LIBCCOIN_COMPAT_H__ */
