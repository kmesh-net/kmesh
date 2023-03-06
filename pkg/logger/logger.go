/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
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
 * Create: 2021-10-09
 */

//Package logger log constructor
package logger

import (
	"io"
	"os"
	"path/filepath"
	"time"

	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	"github.com/sirupsen/logrus"
)

const (
	logSubsys = "subsys"
)

var (
	defaultLogger = InitializeDefaultLogger()

	defaultLogLevel           = logrus.InfoLevel
	defaultLogFile            = "/var/run/kmesh/daemon.log"
	defaultLogMaxFileCnt uint = 12

	defaultLogFormat = &logrus.TextFormatter{
		DisableColors:    true,
		DisableTimestamp: false,
	}
)

// InitializeDefaultLogger return a initialized logger
func InitializeDefaultLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetFormatter(defaultLogFormat)
	logger.SetLevel(defaultLogLevel)

	path, _ := filepath.Split(defaultLogFile)
	err := os.MkdirAll(path, 0750)
	if err != nil {
		logger.Fatal("failed to create log directory")
	}

	file, err := rotatelogs.New(
		defaultLogFile+"-%Y%m%d%H%M",
		rotatelogs.WithLinkName(defaultLogFile),
		rotatelogs.WithRotationCount(defaultLogMaxFileCnt),
		rotatelogs.WithRotationTime(time.Hour),
	)
	if err != nil {
		logger.Fatal(err)
	}

	logger.SetOutput(io.MultiWriter(os.Stdout, file))

	return logger
}

// NewLoggerField allocates a new log entry and adds a field to it.
func NewLoggerField(pkgSubsys string) *logrus.Entry {
	return defaultLogger.WithField(logSubsys, pkgSubsys)
}
