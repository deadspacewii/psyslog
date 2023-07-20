package rfc3164

import (
	"bytes"
	"github.com/deadspacewii/psyslog/common"
	"math"
	"strings"
	"time"
)

const (
	//https://tools.ietf.org/html/rfc3164#section-4.1
	MAXPACKETLEN = 5120
	TAGDELIMITER = ':'
)

type TagFunc[T any] func(string) *T

type ContentFunc[D any] func(string) *D

type Parser[T any, D any] struct {
	buff                  []byte
	index                 int
	l                     int
	priority              *common.Priority
	header                *header
	message               *message
	location              *time.Location
	customTagDelimiter    byte
	customTimestampFormat string
	customTagFunc         TagFunc[T]
	customContentFunc     ContentFunc[D]
}

type ResultRFC3164[T any, D any] struct {
	Priority      int       `json:"priority"`
	Facility      int       `json:"facility"`
	Severity      int       `json:"severity"`
	Timestamp     time.Time `json:"timestamp"`
	Hostname      string    `json:"hostname"`
	OriginTag     string    `json:"origin_tag"`
	OriginContent string    `json:"origin_content"`
	Tag           *T        `json:"tag"`
	Content       *D        `json:"content"`
}

type header struct {
	timestamp time.Time
	hostname  string
}

type message struct {
	tag     string
	content string
}

func NewParser[T any, D any]() *Parser[T, D] {
	return &Parser[T, D]{}
}

func (p *Parser[T, D]) WithTimestampFormat(s string) {
	p.customTimestampFormat = s
}

func (p *Parser[T, D]) WithLocation(location string) {
	switch location {
	case "UTC":
		p.location = time.UTC
	case "Local":
		p.location = time.Local
	default:
		lic, err := time.LoadLocation(location)
		if err == nil {
			p.location = lic
		}
	}
}

func (p *Parser[T, D]) WithTagDelimiter(s byte) {
	p.customTagDelimiter = s
}

func (p *Parser[T, D]) WithTagFunc(t TagFunc[T]) {
	p.customTagFunc = t
}

func (p *Parser[T, D]) WithContentFunc(d ContentFunc[D]) {
	p.customContentFunc = d
}

func (p *Parser[T, D]) Parse(s string) error {
	buff := []byte(s)
	p.buff = buff
	p.l = int(math.Min(MAXPACKETLEN, float64(len(buff))))
	p.index = 0

	pri, err := p.parsePriority()
	if err != nil {
		return err
	}

	p.priority = pri

	hdr, err := p.parseHeader()
	if err != nil {
		return err
	}

	p.header = hdr

	if p.buff[p.index] == ' ' {
		p.index++
	}

	msg, err := p.parsemessage()
	if err != common.ErrEOL {
		return err
	}

	p.message = msg

	return nil
}

func (p *Parser[T, D]) Dump() *ResultRFC3164[T, D] {
	res := ResultRFC3164[T, D]{
		Priority:      p.priority.Priority,
		Facility:      p.priority.Facility,
		Severity:      p.priority.Severity,
		Timestamp:     p.header.timestamp,
		Hostname:      p.header.hostname,
		OriginTag:     p.message.tag,
		OriginContent: p.message.content,
	}

	if p.customTagFunc != nil {
		tag := p.customTagFunc(p.message.tag)
		if tag != nil {
			res.Tag = tag
		}
	}

	if p.customContentFunc != nil {
		content := p.customContentFunc(p.message.content)
		if content != nil {
			res.Content = content
		}
	}

	return &res
}

/*func (p *Parser[T, D]) Dump() common.Parts {
	return common.Parts{
		"timestamp": p.header.timestamp,
		"hostname":  p.header.hostname,
		"tag":       p.message.tag,
		"content":   p.message.content,
		"priority":  p.priority.Priority,
		"facility":  p.priority.Facility,
		"severity":  p.priority.Severity,
	}
}*/

func (p *Parser[T, D]) parsePriority() (*common.Priority, error) {
	return common.ParsePriority(
		p.buff, &p.index, p.l,
	)
}

// HEADER: TIMESTAMP + HOSTNAME (or IP)
// https://tools.ietf.org/html/rfc3164#section-4.1.2
func (p *Parser[T, D]) parseHeader() (*header, error) {
	var err error

	if p.buff[p.index] == ' ' {
		p.index++
	}

	ts, err := p.parseTimestamp()
	if err != nil {
		return nil, err
	}

	h, err := p.parseHostname()
	if err != nil {
		return nil, err
	}

	hdr := &header{
		timestamp: ts,
		hostname:  h,
	}

	return hdr, nil
}

func (p *Parser[T, D]) parseTimestamp() (time.Time, error) {
	var ts time.Time
	var err error
	var tsFmtLen int
	var sub []byte

	tsFmts := []string{
		"Jan 02 15:04:05",
		"Jan 02 15:04:05",
	}

	if p.customTimestampFormat != "" {
		tsFmts = []string{
			p.customTimestampFormat,
		}
	}

	found := false
	for _, tsFmt := range tsFmts {
		tsFmtLen = len(tsFmt)

		if p.index+tsFmtLen > p.l {
			continue
		}

		sub = p.buff[p.index : tsFmtLen+p.index]
		if p.location != nil {
			n := strings.LastIndex(tsFmt, "-07")
			timeStamp := string(sub)
			localTimes := ""
			if n != -1 {
				localTimes = timeStamp[:n]
				tsFmt = tsFmt[:n]
			} else {
				localTimes = timeStamp
			}
			ts, err = time.ParseInLocation(
				tsFmt, localTimes, p.location,
			)
		} else {
			ts, err = time.Parse(
				tsFmt, string(sub),
			)
		}

		if err == nil {
			found = true
			break
		}
	}

	if !found {
		return ts, common.ErrTimestampUnknownFormat
	}

	fixTimestampIfNeeded(&ts)

	p.index += tsFmtLen

	if (p.index < p.l) && (p.buff[p.index] == ' ') {
		p.index++
	}

	return ts, nil
}

func fixTimestampIfNeeded(ts *time.Time) {
	now := time.Now()
	y := ts.Year()

	if ts.Year() == 0 {
		y = now.Year()
	}

	newTs := time.Date(
		y, ts.Month(), ts.Day(),
		ts.Hour(), ts.Minute(), ts.Second(), ts.Nanosecond(),
		ts.Location(),
	)

	*ts = newTs
}

func (p *Parser[T, D]) parseHostname() (string, error) {
	return common.ParseHostname(
		p.buff, &p.index, p.l,
	)
}

// MSG: TAG + CONTENT
// https://tools.ietf.org/html/rfc3164#section-4.1.3
func (p *Parser[T, D]) parsemessage() (*message, error) {
	var err error

	tag, err := p.parseTag()
	if err != nil {
		return nil, err
	}

	content, err := p.parseContent()
	if err != common.ErrEOL {
		return nil, err
	}

	msg := &message{
		tag:     tag,
		content: content,
	}

	return msg, err
}

// http://tools.ietf.org/html/rfc3164#section-4.1.3
func (p *Parser[T, D]) parseTag() (string, error) {
	var b byte
	var tag []byte
	var err error
	var delimiter byte

	if p.customTagDelimiter == 0 {
		delimiter = TAGDELIMITER
	} else {
		delimiter = p.customTagDelimiter
	}

	previous := p.index

	// "The TAG is a string of ABNF alphanumeric characters that MUST NOT exceed 32 characters."
	to := int(
		math.Min(
			float64(p.l),
			float64(p.index+32),
		),
	)

	for p.index < to {
		b = p.buff[p.index]

		if b == delimiter {
			p.index++
			break
		}

		tag = append(tag, b)
		p.index++
	}

	if len(tag) == 0 {
		p.index = previous
	}

	return string(tag), err
}

func (p *Parser[T, D]) parseContent() (string, error) {
	if p.index > p.l {
		return "", common.ErrEOL
	}

	content := bytes.Trim(
		p.buff[p.index:p.l], " ",
	)

	p.index += len(content)

	return string(content), common.ErrEOL
}
