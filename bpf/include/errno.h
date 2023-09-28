/*
 * Copyright 2023 The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.

 * Author: LemmyHuang
 * Create: 2021-09-17
 */

#ifndef _ERRNO_H_
#define _ERRNO_H_

#ifndef ENOENT
#define ENOENT		2  /* No such file or directory */
#endif

#ifndef ENOEXEC
#define ENOEXEC		8  /* Exec format error */
#endif

#ifndef EAGAIN
#define EAGAIN		11  /* Try again */
#endif

#ifndef EBUSY
#define EBUSY		16  /* Device or resource busy */
#endif

#ifndef EINVAL
#define EINVAL		22  /* Invalid argument */
#endif

#ifndef ENOSPC
#define ENOSPC		28  /* No space left on device */
#endif

#endif // _ERRNO_H_