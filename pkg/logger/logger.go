/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: LemmyHuang
 * Create: 2021-10-09
 */

package logger

import (
	"io"
	"os"
	"path/filepath"
	"time"

	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	"github.com/sirupsen/logrus"
)

/*
	logrus.Trace()
	logrus.Debug()
	logrus.Info()
	logrus.Warn()
	logrus.Error()
	logrus.Fatal()
	logrus.Panic()
*/

const (
	LogSubsys = "subsys"
	pkgSubsys = "logger"
)

var (
	DefaultLogger = InitializeDefaultLogger()

	DefaultLogLevel = logrus.DebugLevel
	DefaultLogFile = "/var/run/kmesh/daemon.log"

	DefaultLogFormat = &logrus.TextFormatter {
		DisableColors:	  true,
		DisableTimestamp: false,
	}
)

func InitializeDefaultLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetFormatter(DefaultLogFormat)
	logger.SetLevel(DefaultLogLevel)

	path, _ := filepath.Split(DefaultLogFile)
	err := os.MkdirAll(path, 0750)
	if err != nil {
		logger.Fatal(err)
	}

	file, err := rotatelogs.New(
		DefaultLogFile + "-%Y%m%d%H%M",
		rotatelogs.WithLinkName(DefaultLogFile),
		rotatelogs.WithRotationCount(12),
		rotatelogs.WithRotationTime(time.Hour),
	)
	if err != nil {
		logger.Fatal(err)
	}

	logger.SetOutput(io.MultiWriter(os.Stdout, file))

	return logger
}

