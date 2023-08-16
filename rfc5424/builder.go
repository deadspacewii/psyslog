package rfc5424

import (
	"fmt"
	"github.com/deadspacewii/psyslog/common"
	"strings"
)

type Builder struct {
	priority       int
	version        int
	timestamp      string
	hostName       string
	appName        string
	procId         string
	msgId          string
	structuredData string
	message        string
	result         string
}

func NewBuilder() *Builder {
	return &Builder{
		hostName: "-",
	}
}

func (b *Builder) SetPriority(priority int) *Builder {
	b.priority = priority
	return b
}

func (b *Builder) SetVersion(version int) *Builder {
	b.version = version
	return b
}

func (b *Builder) SetTimestamp(timestamp string) *Builder {
	b.timestamp = timestamp
	return b
}

func (b *Builder) SetHostName(hostName string) *Builder {
	b.hostName = strings.TrimSpace(hostName)
	return b
}

func (b *Builder) SetAppName(appName string) *Builder {
	b.appName = strings.TrimSpace(appName)
	return b
}

func (b *Builder) SetProcId(procId string) *Builder {
	b.procId = strings.TrimSpace(procId)
	return b
}

func (b *Builder) SetMsgId(msgId string) *Builder {
	b.msgId = strings.TrimSpace(msgId)
	return b
}

func (b *Builder) SetStructuredData(structuredData string) *Builder {
	b.structuredData = strings.TrimSpace(structuredData)
	return b
}

func (b *Builder) SetMessage(message string) *Builder {
	b.message = strings.TrimSpace(message)
	return b
}

func (b *Builder) check() error {
	if err := common.CheckPriority(b.priority); err != nil {
		return err
	}

	if err := checkVersion(b.version); err != nil {
		return err
	}

	if err := checkTimestamp(b.timestamp); err != nil {
		return err
	}

	if err := checkHostName(b.hostName); err != nil {
		return err
	}

	return nil
}

func checkVersion(version int) error {
	if version == 0 {
		return common.ErrVersionNotFound
	}

	return nil
}

func checkTimestamp(timestamp string) error {
	buff := []byte(timestamp)
	l := len(buff)
	index := 0
	_, err := parseDate(buff, &index, l)
	if err != nil {
		return err
	}

	return nil
}

func checkHostName(hostName string) error {
	for _, item := range hostName {
		if item == ' ' {
			return common.ErrHostNameContainSpace
		}
	}

	return nil
}

func (b *Builder) Build() error {
	if err := b.check(); err != nil {
		return err
	}

	var (
		ts, appName, procId, msgId, data string
	)

	if b.timestamp == "" {
		ts = string(NILVALUE)
	} else {
		ts = b.timestamp
	}

	if b.appName == "" {
		appName = string(NILVALUE)
	} else {
		appName = b.appName
	}

	if b.procId == "" {
		procId = string(NILVALUE)
	} else {
		procId = b.procId
	}

	if b.msgId == "" {
		msgId = string(NILVALUE)
	} else {
		msgId = b.msgId
	}

	if b.structuredData == "" {
		data = string(NILVALUE)
	} else {
		data = fmt.Sprintf("[%s]", b.structuredData)
	}

	log := fmt.Sprintf(RFC5424FORMAT, b.priority, b.version, ts, b.hostName, appName, procId, msgId, data)

	if b.message != "" {
		log += fmt.Sprintf(" %s", b.message)
	}

	b.result = log
	return nil
}

func (b *Builder) String() string {
	return b.result
}
