/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <ccoin/log.h>

#include <time.h>                       // for localtime, strftime, time, etc

char *str_timenow() {
    static char time_buf[22];
    time_t now;
    struct tm *tm_now;

    time(&now);
    tm_now = localtime(&now);

    strftime(time_buf, 21, "%F %T ", tm_now);

    return time_buf;
}
