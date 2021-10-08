/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

package logger

import (
	"os"
	"io"
	"time"
	"path/filepath"

	"github.com/sirupsen/logrus"
	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
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
	logger.Formatter = DefaultLogFormat
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

