package main

import (
	"fmt"
	"github.com/deadspacewii/psyslog/rfc5424"
	"log"
)

func main() {
	builder := rfc5424.NewBuilder()
	builder.SetPriority(136)
	builder.SetVersion(1)
	builder.SetTimestamp("2003-08-24T05:14:15.000003-07:00")
	builder.SetHostName("test.com")
	builder.SetStructuredData("test value for RFC5424")
	builder.SetMessage("test message")

	if err := builder.Build(); err != nil {
		log.Fatal(err.Error())
	}

	fmt.Println(builder.String())
}
