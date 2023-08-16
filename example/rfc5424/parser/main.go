package main

import (
	"encoding/json"
	"fmt"
	"github.com/deadspacewii/psyslog/rfc5424"
	"log"
	"regexp"
	"strconv"
	"strings"
)

var testLog = `<189>1 2003-08-24T05:14:15.000003-07:00 8.35.34.57 ATIC - -[log_type=device_drop_flow time="2021-07-14 16:24:40" device_ip=8.35.34.57 ]`

type TestContent struct {
	LogType      string `json:"log_type"`
	Time         string `json:"time"`
	IsIpLocation bool   `json:"is_ipLocation"`
}

func parserContent(s string) (TestContent, error) {
	array := make([]string, 0)
	content := TestContent{}
	s = strings.TrimSpace(s[1 : len(s)-1])
	re := regexp.MustCompile(`( .*?=".*?" )`)

	match := re.FindAllString(s, -1)

	for _, item := range match {
		item = strings.TrimSpace(item)
		array = append(array, item)
		s = strings.ReplaceAll(s, item, "")
	}

	re = regexp.MustCompile(`(.*?=.*? )`)
	match = re.FindAllString(s, -1)

	for _, item := range match {
		s = strings.ReplaceAll(s, item, "")
		item = strings.TrimSpace(item)
		array = append(array, item)
	}
	array = append(array, strings.TrimSpace(s))
	jsonStr := parserValue2Json(array)
	if err := json.Unmarshal([]byte(jsonStr), &content); err != nil {
		log.Fatal(err.Error())
		return TestContent{}, err
	}

	return content, nil
}

func parserValue2Json(array []string) string {
	jsonStr := `{`
	tempArray := []string{}
	for _, item := range array {
		strs := strings.Split(item, "=")
		if strs[1][0] != '"' && strs[1][len(strs[1])-1] != '"' && strs[1] != "false" && strs[1] != "true" {
			_, err := strconv.Atoi(strs[1])
			if err != nil {
				v := fmt.Sprintf("\"%s\":\"%s\"", strs[0], strs[1])
				tempArray = append(tempArray, v)
			} else {
				v := fmt.Sprintf("\"%s\":%s", strs[0], strs[1])
				tempArray = append(tempArray, v)
			}
		} else {
			v := fmt.Sprintf("\"%s\":%s", strs[0], strs[1])
			tempArray = append(tempArray, v)
		}
	}

	jsonStr += strings.Join(tempArray, ",") + `}`
	return jsonStr
}

func main() {
	parser := rfc5424.NewParser[TestContent]()
	parser.WithStructuredDataFunc(parserContent)

	if err := parser.Parse(testLog); err != nil {
		log.Fatal(err.Error())
	}

	result := parser.Dump()
	fmt.Println(result.Timestamp)
}
