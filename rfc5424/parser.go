package rfc5424

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/deadspacewii/psyslog/common"
	"math"
	"strconv"
	"time"
)

var (
	ErrYearInvalid       = errors.New("Invalid year in timestamp")
	ErrMonthInvalid      = errors.New("Invalid month in timestamp")
	ErrDayInvalid        = errors.New("Invalid day in timestamp")
	ErrHourInvalid       = errors.New("Invalid hour in timestamp")
	ErrMinuteInvalid     = errors.New("Invalid hour in timestamp")
	ErrSecondInvalid     = errors.New("Invalid second in timestamp")
	ErrSecFracInvalid    = errors.New("Invalid fraction of second in timestamp")
	ErrTimeZoneInvalid   = errors.New("Invalid time zone in timestamp")
	ErrInvalidTimeFormat = errors.New("Invalid time format")
	ErrInvalidAppName    = errors.New("Invalid app name")
	ErrInvalidProcId     = errors.New("Invalid proc ID")
	ErrInvalidMsgId      = errors.New("Invalid msg ID")
	ErrNoStructuredData  = errors.New("No structured data")
)

type Parser struct {
	buff           []byte
	index          int
	l              int
	header         *header
	structuredData string
	message        string
}

type header struct {
	priority  *common.Priority
	version   int
	timestamp time.Time
	hostname  string
	appName   string
	procId    string
	msgId     string
}

type fullDate struct {
	year  int
	month int
	day   int
}

type fullTime struct {
	pt  *partialTime
	loc *time.Location
}

type partialTime struct {
	hour    int
	minute  int
	seconds int
	secFrac float64
}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(s string) error {
	buff := []byte(s)
	p.buff = buff
	p.l = int(math.Min(MAXPACKETLEN, float64(len(buff))))
	p.index = 0

	hdr, err := p.parseHeader()
	if err != nil {
		return err
	}

	p.header = hdr

	sd, err := p.parseStructuredData()
	if err != nil {
		return err
	}

	p.structuredData = sd
	p.index++

	if p.index < p.l {
		p.message = string(
			bytes.Trim(
				p.buff[p.index:p.l], " ",
			),
		)
	}

	return nil
}

func (p *Parser) Dump() common.Parts {
	return common.Parts{
		"priority":        p.header.priority.Priority,
		"facility":        p.header.priority.Facility,
		"severity":        p.header.priority.Severity,
		"version":         p.header.version,
		"timestamp":       p.header.timestamp,
		"hostname":        p.header.hostname,
		"app_name":        p.header.appName,
		"proc_id":         p.header.procId,
		"msg_id":          p.header.msgId,
		"structured_data": p.structuredData,
		"message":         p.message,
	}
}

// HEADER = PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID
func (p *Parser) parseHeader() (*header, error) {
	pri, err := p.parsePriority()
	if err != nil {
		return nil, err
	}

	ver, err := p.parseVersion()
	if err != nil {
		return nil, err
	}

	p.index++

	ts, err := p.parseTimestamp()
	if err != nil {
		return nil, err
	}

	p.index++

	host, err := p.parseHostname()
	if err != nil {
		return nil, err
	}

	appName, err := p.parseAppName()
	if err != nil {
		return nil, err
	}

	p.index++

	procId, err := p.parseProcId()
	if err != nil {
		return nil, err
	}

	p.index++

	msgId, err := p.parseMsgId()
	if err != nil {
		return nil, err
	}

	hdr := &header{
		version:   ver,
		timestamp: *ts,
		priority:  pri,
		hostname:  host,
		procId:    procId,
		msgId:     msgId,
		appName:   appName,
	}

	return hdr, nil
}

func (p *Parser) parsePriority() (*common.Priority, error) {
	return common.ParsePriority(
		p.buff, &p.index, p.l,
	)
}

func (p *Parser) parseVersion() (int, error) {
	return common.ParseVersion(p.buff, &p.index, p.l)
}

// https://tools.ietf.org/html/rfc5424#section-6.2.3
func (p *Parser) parseTimestamp() (*time.Time, error) {
	if p.buff[p.index] == NILVALUE {
		p.index++
		return new(time.Time), nil
	}

	fd, err := parseFullDate(
		p.buff, &p.index, p.l,
	)

	if err != nil {
		return nil, err
	}

	if p.buff[p.index] != 'T' {
		return nil, ErrInvalidTimeFormat
	}

	p.index++

	ft, err := parseFullTime(
		p.buff, &p.index, p.l,
	)

	if err != nil {
		return nil, common.ErrTimestampUnknownFormat
	}

	nSec, err := toNSec(
		ft.pt.secFrac,
	)

	if err != nil {
		return nil, err
	}

	ts := time.Date(
		fd.year,
		time.Month(fd.month),
		fd.day,
		ft.pt.hour,
		ft.pt.minute,
		ft.pt.seconds,
		nSec,
		ft.loc,
	)

	return &ts, nil
}

// HOSTNAME = NILVALUE / 1*255PRINTUSASCII
func (p *Parser) parseHostname() (string, error) {
	h, err := common.ParseHostname(p.buff, &p.index, p.l)

	p.index++

	return h, err
}

// APP-NAME = NILVALUE / 1*48PRINTUSASCII
func (p *Parser) parseAppName() (string, error) {
	return common.ParseUpToLen(p.buff, &p.index, p.l, 48, ErrInvalidAppName)
}

// PROCID = NILVALUE / 1*128PRINTUSASCII
func (p *Parser) parseProcId() (string, error) {
	return common.ParseUpToLen(p.buff, &p.index, p.l, 128, ErrInvalidProcId)
}

// MSGID = NILVALUE / 1*32PRINTUSASCII
func (p *Parser) parseMsgId() (string, error) {
	return common.ParseUpToLenOrData(
		p.buff, &p.index, p.l, 32, ErrInvalidMsgId,
	)
}

func (p *Parser) parseStructuredData() (string, error) {
	return parseStructuredData(p.buff, &p.index, p.l)
}

// FULL-DATE : DATE-FULLYEAR "-" DATE-MONTH "-" DATE-MDAY
func parseFullDate(buff []byte, cursor *int, l int) (fullDate, error) {
	var fd fullDate

	year, err := parseYear(buff, cursor, l)
	if err != nil {
		return fd, err
	}

	if buff[*cursor] != '-' {
		return fd, common.ErrTimestampUnknownFormat
	}

	*cursor++

	month, err := parseMonth(buff, cursor, l)
	if err != nil {
		return fd, err
	}

	if buff[*cursor] != '-' {
		return fd, common.ErrTimestampUnknownFormat
	}

	*cursor++

	day, err := parseDay(buff, cursor, l, year, month)
	if err != nil {
		return fd, err
	}

	fd = fullDate{
		year:  year,
		month: month,
		day:   day,
	}

	return fd, nil
}

func parseYear(buff []byte, index *int, l int) (int, error) {
	yearLen := 4

	if *index+yearLen > l {
		return 0, common.ErrEOL
	}

	yearSub := buff[*index : *index+yearLen]

	*index += yearLen
	year, err := strconv.Atoi(string(yearSub))
	if err != nil {
		return 0, ErrYearInvalid
	}

	return year, nil
}

// DATE-MONTH = 2DIGIT  ; 01-12
func parseMonth(buff []byte, index *int, l int) (int, error) {
	return common.Parse2Digits(buff, index, l, 1, 12, ErrMonthInvalid)
}

// DATE-MDAY = 2DIGIT  ; 01-28, 01-29, 01-30, 01-31 based on month/year
func parseDay(buff []byte, index *int, l int, year, month int) (int, error) {
	switch month {
	case 1, 3, 5, 7, 8, 10, 12:
		return common.Parse2Digits(buff, index, l, 1, 31, ErrDayInvalid)
	case 4, 6, 9, 11:
		return common.Parse2Digits(buff, index, l, 1, 30, ErrDayInvalid)
	case 2:
		if year%4 == 0 && year%100 != 0 || year%400 == 0 {
			return common.Parse2Digits(buff, index, l, 1, 29, ErrDayInvalid)
		} else {
			return common.Parse2Digits(buff, index, l, 1, 28, ErrDayInvalid)
		}
	}
	return 0, ErrDayInvalid
}

// FULL-TIME = PARTIAL-TIME TIME-OFFSET
func parseFullTime(buff []byte, cursor *int, l int) (*fullTime, error) {
	pt, err := parsePartialTime(buff, cursor, l)
	if err != nil {
		return nil, err
	}

	loc, err := parseTimeOffset(buff, cursor, l)
	if err != nil {
		return nil, err
	}

	ft := &fullTime{
		pt:  pt,
		loc: loc,
	}

	return ft, nil
}

// PARTIAL-TIME = TIME-HOUR ":" TIME-MINUTE ":" TIME-SECOND[TIME-SECFRAC]
func parsePartialTime(buff []byte, index *int, l int) (*partialTime, error) {
	hour, minute, err := parseHourMinute(
		buff, index, l,
	)

	if err != nil {
		return nil, err
	}

	if buff[*index] != ':' {
		return nil, ErrInvalidTimeFormat
	}

	*index++

	// ----

	seconds, err := parseSecond(
		buff, index, l,
	)

	if err != nil {
		return nil, err
	}

	pt := &partialTime{
		hour:    hour,
		minute:  minute,
		seconds: seconds,
	}

	// ----

	if buff[*index] != '.' {
		return pt, nil
	}

	*index++

	secFrac, err := parseSecFrac(
		buff, index, l,
	)

	if err != nil {
		return pt, nil
	}

	pt.secFrac = secFrac

	return pt, nil
}

func parseHourMinute(buff []byte, index *int, l int) (int, int, error) {
	hour, err := parseHour(buff, index, l)
	if err != nil {
		return 0, 0, err
	}

	if buff[*index] != ':' {
		return 0, 0, ErrInvalidTimeFormat
	}
	*index++

	minute, err := parseMinute(buff, index, l)
	if err != nil {
		return 0, 0, err
	}

	return hour, minute, nil
}

// TIME-HOUR = 2DIGIT  ; 00-23
func parseHour(buff []byte, index *int, l int) (int, error) {
	return common.Parse2Digits(buff, index, l, 0, 23, ErrHourInvalid)
}

// TIME-MINUTE = 2DIGIT  ; 00-59
func parseMinute(buff []byte, index *int, l int) (int, error) {
	return common.Parse2Digits(buff, index, l, 0, 59, ErrMinuteInvalid)
}

// TIME-SECOND = 2DIGIT  ; 00-59
func parseSecond(buff []byte, index *int, l int) (int, error) {
	return common.Parse2Digits(buff, index, l, 0, 59, ErrSecondInvalid)
}

// TIME-SECFRAC = "." 1*6DIGIT
func parseSecFrac(buff []byte, index *int, l int) (float64, error) {
	maxDigitLen := 6

	max := *index + maxDigitLen
	from := *index
	to := 0

	for to = from; to < max; to++ {
		if to >= l {
			break
		}

		c := buff[to]
		if !common.IsDigit(c) {
			break
		}
	}

	sub := string(buff[from:to])
	if len(sub) == 0 {
		return 0, ErrSecFracInvalid
	}

	secFrac, err := strconv.ParseFloat("0."+sub, 64)
	if err != nil {
		return 0, ErrSecFracInvalid
	}

	*index = to

	return secFrac, nil
}

// TIME-OFFSET = "Z" / TIME-NUMOFFSET
func parseTimeOffset(buff []byte, index *int, l int) (*time.Location, error) {

	if buff[*index] == 'Z' {
		*index++
		return time.UTC, nil
	}

	return parseNumericalTimeOffset(buff, index, l)
}

// TIME-NUMOFFSET  = ("+" / "-") TIME-HOUR ":" TIME-MINUTE
func parseNumericalTimeOffset(buff []byte, index *int, l int) (*time.Location, error) {
	var loc = new(time.Location)

	sign := buff[*index]

	if (sign != '+') && (sign != '-') {
		return loc, ErrTimeZoneInvalid
	}

	*index++

	hour, minute, err := parseHourMinute(buff, index, l)
	if err != nil {
		return loc, err
	}

	tzStr := fmt.Sprintf("%s%02d:%02d", string(sign), hour, minute)
	tmpTs, err := time.Parse(SUBSIDIARYTIMEFORMAT, SUBSIDIARYTIMECHILDFORMAT+tzStr)
	if err != nil {
		return loc, err
	}

	return tmpTs.Location(), nil
}

func toNSec(sec float64) (int, error) {
	_, frac := math.Modf(sec)
	fracStr := strconv.FormatFloat(frac, 'f', 9, 64)
	fracInt, err := strconv.Atoi(fracStr[2:])
	if err != nil {
		return 0, err
	}

	return fracInt, nil
}

// https://tools.ietf.org/html/rfc5424#section-6.3
func parseStructuredData(buff []byte, index *int, l int) (string, error) {
	var sdData string
	var found bool

	if buff[*index] == NILVALUE {
		*index++
		return "-", nil
	}

	if buff[*index] != '[' {
		return sdData, ErrNoStructuredData
	}

	from := *index
	to := 0

	for to = from; to < l; to++ {
		if found {
			break
		}

		b := buff[to]

		if b == ']' {
			switch t := to + 1; {
			case t == l:
				found = true
			case t <= l && buff[t] == ' ':
				found = true
			}
		}
	}

	if found {
		*index = to
		return string(buff[from:to]), nil
	}

	return sdData, ErrNoStructuredData
}
