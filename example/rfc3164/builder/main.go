package main

import (
	"fmt"
	"github.com/deadspacewii/psyslog/rfc3164"
	"log"
)

func main() {
	builder := rfc3164.NewBuilder()
	builder.SetDelimiter(':')
	builder.SetHostName("test.com")
	builder.SetTag("%%01AES/01/(l)")
	builder.SetContent("this is a message")

	if err := builder.Build(); err != nil {
		log.Fatal(err.Error())
	}

	fmt.Println(builder.String())
}
