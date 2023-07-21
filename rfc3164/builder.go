package rfc3164

import (
	"fmt"
	"github.com/deadspacewii/psyslog/common"
	"strings"
	"time"
)

type Builder struct {
	timestamp string `json:"Timestamp"`
	priority  int    `json:"priority"`
	hostName  string `json:"hostName"`
	tag       string `json:"tag"`
	delimiter byte   `json:"delimiter"`
	content   string `json:"content"`
	result    string `json:"result"`
}

func NewBuilder() *Builder {
	return &Builder{
		hostName: "-",
		tag:      "-",
		content:  "-",
	}
}

func (b *Builder) SetPriority(priority int) *Builder {
	b.priority = priority
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

func (b *Builder) SetDelimiter(delimiter byte) *Builder {
	b.delimiter = delimiter
	return b
}

func (b *Builder) SetTag(tag string) *Builder {
	b.tag = tag
	return b
}

func (b *Builder) SetContent(content string) *Builder {
	b.content = content
	return b
}

func (b *Builder) setLocalTime() *Builder {
	if b.timestamp == "" {
		b.timestamp = time.Now().Format(DEFAULTTIMESTAMPFORMAT)
	}
	return b
}

func (b *Builder) check() error {
	if err := checkPriority(b.priority); err != nil {
		return err
	}

	if err := checkHostName(b.hostName); err != nil {
		return err
	}

	if err := checkTag(b.tag, b.delimiter); err != nil {
		return err
	}

	return nil
}

func checkPriority(priority int) error {
	if priority < 0 || priority > 191 {
		return common.ErrPriorityBeyondNumber
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

func checkTag(tag string, deli byte) error {
	var delimter byte
	if deli == 0 {
		delimter = TAGDELIMITER
	} else {
		delimter = deli
	}

	if len(tag) > 32 {
		return common.ErrTagTooLong
	}

	for i := 0; i < len(tag); i++ {
		if tag[i] == delimter {
			return common.ErrHostNameContainSpace
		}
	}

	return nil
}

func (b *Builder) Build() error {
	if err := b.check(); err != nil {
		return err
	}

	b.setLocalTime()

	b.result = fmt.Sprintf(RFC3164fORMAT, b.priority, b.timestamp, b.hostName, b.tag, string(b.delimiter), b.content)
	return nil
}

func (b *Builder) String() string {
	return b.result
}
