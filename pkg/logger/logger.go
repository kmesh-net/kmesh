/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

package logger

import (
	"os"
	"github.com/sirupsen/logrus"
)

const (
	LogSubsys = "subsys"
)

var (
	DefaultLogger = InitializeDefaultLogger()

	DefaultLogLevel = logrus.DebugLevel
	DefaultLogFile = os.Stdout

	DefaultLogFormat = &logrus.TextFormatter {
		DisableColors:	  true,
		DisableTimestamp: false,
	}
)

func InitializeDefaultLogger() *logrus.Logger {
	logger := logrus.New()
	logger.Formatter = DefaultLogFormat
	logger.SetLevel(DefaultLogLevel)
	logger.SetOutput(DefaultLogFile)
	return logger
}

/*
logrus.Trace()
logrus.Debug()
logrus.Info()
logrus.Warn()
logrus.Error()
logrus.Fatal()
logrus.Panic()
*/
