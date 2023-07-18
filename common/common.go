package common

import (
	"errors"
	"strconv"
)

const (
	RFC_3164 = iota + 1
)

type Parts map[string]interface{}

var (
	ErrEOL     = errors.New("End of log line")
	ErrNoSpace = errors.New("No space found")

	ErrPriorityNoStart  = errors.New("No start char found for priority")
	ErrPriorityEmpty    = errors.New("Priority field empty")
	ErrPriorityNoEnd    = errors.New("No end char found for priority")
	ErrPriorityTooShort = errors.New("Priority field too short")
	ErrPriorityTooLong  = errors.New("Priority field too short")
	ErrPriorityNonDigit = errors.New("Priority field too short")

	ErrTimestampUnknownFormat = errors.New("Timestamp format unknown")
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

func FindNextSpace(buff []byte, from, l int) (int, error) {
	for to := from; to < l; to++ {
		if buff[to] == ' ' {
			to++
			return to, nil
		}
	}

	return 0, ErrNoSpace
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
