/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Kmesh */

#ifndef _ERRNO_H_
#define _ERRNO_H_

#ifndef ENOENT
#define ENOENT 2 /* No such file or directory */
#endif

#ifndef ENOEXEC
#define ENOEXEC 8 /* Exec format error */
#endif

#ifndef EAGAIN
#define EAGAIN 11 /* Try again */
#endif

#ifndef EBUSY
#define EBUSY 16 /* Device or resource busy */
#endif

#ifndef EINVAL
#define EINVAL 22 /* Invalid argument */
#endif

#ifndef ENOSPC
#define ENOSPC 28 /* No space left on device */
#endif

#endif // _ERRNO_H_