/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
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