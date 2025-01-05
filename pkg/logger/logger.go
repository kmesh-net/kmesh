/*
 * Copyright The Kmesh Authors.
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
 */

package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	logSubsys = "subsys"
)

var (
	defaultLogger  = initDefaultLogger()
	fileOnlyLogger = initFileLogger()

	defaultLogLevel = logrus.InfoLevel
	defaultLogFile  = "/var/run/kmesh/daemon.log"

	defaultLogFormat = &logrus.TextFormatter{
		DisableColors:    true,
		DisableTimestamp: false,
	}

	loggerMap = map[string]*logrus.Logger{
		"default":  defaultLogger,
		"fileOnly": fileOnlyLogger,
	}
)

func SetLoggerLevel(loggerName string, level logrus.Level) error {
	logger, exists := loggerMap[loggerName]
	if !exists || logger == nil {
		return fmt.Errorf("logger %s does not exist", loggerName)
	}
	logger.SetLevel(level)
	return nil
}

func GetLoggerLevel(loggerName string) (logrus.Level, error) {
	logger, exists := loggerMap[loggerName]
	if !exists || logger == nil {
		return 0, fmt.Errorf("logger %s does not exist", loggerName)
	}
	return logger.Level, nil
}

func GetLoggerNames() []string {
	names := make([]string, 0, len(loggerMap))
	for loggerName := range loggerMap {
		names = append(names, loggerName)
	}
	return names
}

// initDefaultLogger return a default logger
func initDefaultLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetFormatter(defaultLogFormat)
	logger.SetLevel(defaultLogLevel)
	return logger
}

// initFileLogger return a file only logger
func initFileLogger() *logrus.Logger {
	logger := initDefaultLogger()
	logFilePath := defaultLogFile
	path, fileName := filepath.Split(logFilePath)
	err := os.MkdirAll(path, 0o700)
	if err != nil {
		logger.Warnf("failed to create log directory: %v, consider running with root user", err)
		// if error occurs, fall back to current working directory
		logFilePath = fileName
	}

	logfile := &lumberjack.Logger{
		Filename:   logFilePath,
		MaxSize:    500, // megabytes
		MaxBackups: 3,
		MaxAge:     28,    //days
		Compress:   false, // disabled by default
	}
	logger.SetOutput(io.Writer(logfile))
	return logger
}

// NewLoggerScope allocates a new log entry for a specific scope.
func NewLoggerScope(scope string) *logrus.Entry {
	return defaultLogger.WithField(logSubsys, scope)
}

// NewFileLogger don't output log to stdout
func NewFileLogger(pkgSubsys string) *logrus.Entry {
	return fileOnlyLogger.WithField(logSubsys, pkgSubsys)
}
