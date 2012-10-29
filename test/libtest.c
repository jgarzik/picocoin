
#include "picocoin-config.h"

#include <jansson.h>
#include "libtest.h"

json_t *read_json(const char *filename)
{
	json_error_t err;
	return json_load_file(filename, JSON_REJECT_DUPLICATES, &err);
}

