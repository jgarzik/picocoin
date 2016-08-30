/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <ccoin/log.h>

#include <time.h>                       // for localtime, strftime, time, etc

char *str_timenow(char *time_buf)
{
	time_t now;
	struct tm tm_now;

	time(&now);
	localtime_r(&now, &tm_now);

	strftime(time_buf, 21, "%F %T ", &tm_now);

	return time_buf;
}
