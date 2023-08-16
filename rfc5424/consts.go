package rfc5424

const (
	NILVALUE = '-'

	// according to https://tools.ietf.org/html/rfc5424#section-6.1
	// the length of the packet MUST be 2048 bytes or less.
	// However we will accept a bit more while protecting from exhaustion
	MAXPACKETLEN              = 5120
	SUBSIDIARYTIMEFORMAT      = "2006-01-02 15:04:05-07:00"
	SUBSIDIARYTIMECHILDFORMAT = "2006-01-02 15:04:05"
)

const (
	RFC5424FORMAT = "<%d>%d %s %s %s %s %s %s"
)
