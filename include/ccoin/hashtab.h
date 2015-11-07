#ifndef __LIBCCOIN_HASHTAB_H__
#define __LIBCCOIN_HASHTAB_H__
/* Copyright 2015 BitPay, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	BP_HT_INIT_TAB_SZ	= 11,
	BP_HT_MAX_BUCKET_SZ	= 3,
};

typedef void (*bp_freefunc)(void *);
typedef void (*bp_kvu_func)(void *key, void *value, void *user_private);

struct bp_ht_ent {
	unsigned long		hash;	// hash_f() of key
	void			*key;	// key pointer
	void			*value; // value pointer

	struct bp_ht_ent	*next;	// next record in hash bucket
};

struct bp_hashtab {
	unsigned int	ref;		// reference count
	unsigned int	size;		// table entry count

	struct bp_ht_ent **tab;		// table buckets
	unsigned int	tab_size;	// bucket count

					// key comparison
	unsigned long	(*hash_f)(const void *p);
	bool		(*equal_f)(const void *a, const void *b);

					// key, value destruction

	bp_freefunc	keyfree_f;
	bp_freefunc	valfree_f;
};

extern struct bp_hashtab *bp_hashtab_new_ext(
	unsigned long (*hash_f)(const void *p),
	bool (*equal_f)(const void *a, const void *b),
	bp_freefunc keyfree_f,
	bp_freefunc valfree_f);

static inline struct bp_hashtab *bp_hashtab_new(
	unsigned long (*hash_f)(const void *p),
	bool (*equal_f)(const void *a, const void *b))
{
	return bp_hashtab_new_ext(hash_f, equal_f, NULL, NULL);
}

extern void bp_hashtab_unref(struct bp_hashtab *);
extern bool bp_hashtab_clear(struct bp_hashtab *);

static inline void bp_hashtab_ref(struct bp_hashtab *ht)
{
	ht->ref++;
}

static inline unsigned int bp_hashtab_size(const struct bp_hashtab *ht)
{
	return ht->size;
}

extern bool bp_hashtab_del(struct bp_hashtab *ht, const void *key);
extern bool bp_hashtab_put(struct bp_hashtab *ht, void *key, void *val);
extern bool bp_hashtab_get_ext(struct bp_hashtab *ht, const void *lookup_key,
			       void **orig_key, void **value);

static inline void *bp_hashtab_get(struct bp_hashtab *ht, const void *key)
{
	void *ret_key = NULL;
	void *ret_val = NULL;
	bool rc = bp_hashtab_get_ext(ht, key, &ret_key, &ret_val);
	if (!rc)
		return NULL;

	return ret_val;
}

extern void bp_hashtab_iter(struct bp_hashtab *ht, bp_kvu_func f, void *priv);

#ifdef __cplusplus
}
#endif

#endif /* __LIBCCOIN_HASHTAB_H__ */
