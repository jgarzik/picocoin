#ifndef __LIBCCOIN_LOG_H__
#define __LIBCCOIN_LOG_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdio.h>                      // for fprintf
#include <stdbool.h>                    // for bool

#define log_info(LOGMESSAGE, ...)					\
            if ( log_state->logtofile ) {				\
                fprintf(log_state->stream, "%s" LOGMESSAGE "\n",	\
                    str_timenow(),					\
                    ##__VA_ARGS__);					\
            } else {							\
                fprintf(log_state->stream, LOGMESSAGE "\n", ##__VA_ARGS__); }

#define log_error(LOGMESSAGE, ...)					\
            fprintf(stderr, LOGMESSAGE "\n", ##__VA_ARGS__);		\
            if ( log_state->logtofile ) {				\
                fprintf(log_state->stream, "%s" LOGMESSAGE "\n",	\
                    str_timenow(),					\
                    ##__VA_ARGS__); }

#define log_debug(LOGMESSAGE, ...)					\
            if ( log_state->debug ) {					\
                log_info(LOGMESSAGE, ##__VA_ARGS__); }

#ifdef __cplusplus
extern "C" {
#endif

struct logging {
	FILE *stream;
	bool logtofile;
	bool debug;
};

extern struct logging *log_state;

char *str_timenow();

#ifdef __cplusplus
}
#endif

#endif /* __LIBCCOIN_LOG_H__ */
