package log

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/x-cray/logrus-prefixed-formatter"
	"os"
	"path/filepath"
	"sync"
)

var (
	level      = INFO
	fileLogger = log.New()
	defLogger  = log.New()
	fileMux    = sync.Mutex{}
)

func init() {
	defLogger.SetFormatter(&prefixed.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
		ForceFormatting: true,
	})
	defLogger.SetOutput(os.Stdout)
	defLogger.SetLevel(log.InfoLevel)
	fileLogger.SetFormatter(&prefixed.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
		DisableColors:   true,
		ForceFormatting: true,
	})
	fileLogger.SetLevel(levelMapping[TRACE])
}

func SetLevel(l LogLevel) {
	level = l
	defLogger.SetLevel(levelMapping[level])
}

func Traceln(format string, v ...interface{}) {
	defLogger.Traceln(fmt.Sprintf(format, v...))
}

func Debugln(format string, v ...interface{}) {
	defLogger.Debugln(fmt.Sprintf(format, v...))
}

func Infoln(format string, v ...interface{}) {
	defLogger.Infoln(fmt.Sprintf(format, v...))
}

func Warnln(format string, v ...interface{}) {
	defLogger.Warnln(fmt.Sprintf(format, v...))
}

func Errorln(format string, v ...interface{}) {
	defLogger.Errorln(fmt.Sprintf(format, v...))
}

func Fileln(l LogLevel, data string) {
	if l >= level {
		if f := initFile(filepath.Join(logDir, logFile)); f != nil {
			fileMux.Lock()
			fileLogger.SetOutput(f)
			fileLogger.Logln(levelMapping[l], data)
			fileMux.Unlock()
			_ = f.Close()
		}
	}
}
