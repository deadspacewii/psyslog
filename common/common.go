package common

import (
	"errors"
	"strconv"
)

const (
	NO_VERSION = -1
)

type Parts map[string]interface{}

var (
	ErrEOL     = errors.New("End of log line")
	ErrNoSpace = errors.New("No space found")

	ErrPriorityNoStart      = errors.New("No start char found for priority")
	ErrPriorityEmpty        = errors.New("Priority field empty")
	ErrPriorityNoEnd        = errors.New("No end char found for priority")
	ErrPriorityTooShort     = errors.New("Priority field too short")
	ErrPriorityTooLong      = errors.New("Priority field too long")
	ErrPriorityNonDigit     = errors.New("Priority field is not digit")
	ErrPriorityBeyondNumber = errors.New("Priority must between 0 and 191")

	ErrVersionNotFound = errors.New("Can not find version")

	ErrTimestampUnknownFormat = errors.New("Timestamp format unknown")

	ErrHostNameContainSpace = errors.New("HostName contain space")

	ErrTagTooLong = errors.New("tag field too long")
)

type Priority struct {
	Priority int
	Facility int
	Severity int
}

// https://tools.ietf.org/html/rfc3164#section-4.1
func ParsePriority(buff []byte, index *int, l int) (*Priority, error) {
	if l <= 0 {
		return nil, ErrPriorityEmpty
	}

	if buff[*index] != '<' {
		return nil, ErrPriorityNoStart
	}

	priDigit := 0

	for i := 1; i < l; i++ {
		if i >= 5 {
			return nil, ErrPriorityTooLong
		}

		c := buff[i]

		if c == '>' {
			if i == 1 {
				return nil, ErrPriorityTooShort
			}

			*index = i + 1
			return NewPriority(priDigit), nil
		}

		if IsDigit(c) {
			v, err := strconv.Atoi(string(c))
			if err != nil {
				return nil, err
			}

			priDigit = (priDigit * 10) + v
		} else {
			return nil, ErrPriorityNonDigit
		}
	}

	return nil, ErrPriorityNoEnd
}

// https://tools.ietf.org/html/rfc5424#section-6.2.2
func ParseVersion(buff []byte, index *int, l int) (int, error) {
	if *index >= l {
		return NO_VERSION, ErrVersionNotFound
	}

	c := buff[*index]
	*index++

	if !IsDigit(c) {
		return NO_VERSION, ErrVersionNotFound
	}

	value, err := strconv.Atoi(string(c))
	if err != nil {
		*index--
		return NO_VERSION, err
	}

	return value, nil
}

func IsDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func NewPriority(p int) *Priority {
	return &Priority{
		Priority: p,
		Facility: p / 8,
		Severity: p % 8,
	}
}

func Parse2Digits(buff []byte, index *int, l int, min int, max int, err error) (int, error) {
	digitLen := 2
	if *index+digitLen > l {
		return 0, ErrEOL
	}

	sub := string(buff[*index : *index+digitLen])

	*index += digitLen

	value, e := strconv.Atoi(sub)
	if e != nil {
		return 0, e
	}

	if value < min || value > max {
		return 0, err
	}

	return value, nil
}

func ParseHostname(buff []byte, index *int, l int) (string, error) {
	from := *index
	var to int

	for to = from; to < l; to++ {
		if buff[to] == ' ' {
			break
		}
	}

	hostname := buff[from:to]

	*index = to

	return string(hostname), nil
}

func ParseUpToLen(buff []byte, index *int, l int, maxLen int, e error) (string, error) {
	var to int
	var found bool
	var result string

	max := *index + maxLen

	for to = *index; (to < max) && (to < l); to++ {
		if buff[to] == ' ' {
			found = true
			break
		}
	}

	if found {
		result = string(buff[*index:to])
	}

	*index = to

	if found {
		return result, nil
	}

	return "", e
}

func ParseUpToLenOrData(buff []byte, index *int, l int, maxLen int, e error) (string, error) {
	var to int
	var found bool
	var result string

	max := *index + maxLen

	for to = *index; (to < max) && (to < l); to++ {
		if buff[to] == ' ' || buff[to] == '[' {
			if buff[to] == ' ' {
				to++
			}
			found = true
			break
		}
	}

	if found {
		result = string(buff[*index:to])
	}

	*index = to

	if found {
		return result, nil
	}

	return "", e
}
