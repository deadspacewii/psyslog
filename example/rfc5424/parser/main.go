package main

import (
	"fmt"
	"github.com/deadspacewii/psyslog/rfc5424"
	"log"
)

var testLog = `<189>1 2021-07-14T16:24:40.332+08:00 8.35.34.57 ATIC - -[log_type=device_drop_flow time="2021-07-14 16:24:40" device_ip=8.35.34.57 ]`

func main() {
	parser := rfc5424.NewParser()

	if err := parser.Parse(testLog); err != nil {
		log.Fatal(err.Error())
	}

	result := parser.Dump()
	for k, v := range result {
		fmt.Println(k, ":", v)
	}
}
