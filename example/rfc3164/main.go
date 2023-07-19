package main

import (
	"encoding/json"
	"fmt"
	"github.com/deadspacewii/psyslog/rfc3164"
	"log"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

var testLog = `<189>2022-01-10 17:32:20 8.35.34.57 %%01SEC/5/ATCKDF(l):log_type=ip_flow time="2021-07-14 17:32:20" is_ipLocation=false`

type TestTag struct {
	DD       int    `json:"dd"`
	Module   string `json:"module"`
	Severity int    `json:"severity"`
	Brief    string `json:"brief"`
	LogType  string `json:"LogType"`
}

type TestContent struct {
	LogType      string `json:"log_type"`
	Time         string `json:"time"`
	IsIpLocation bool   `json:"is_ipLocation"`
}

func parserTag(s string) *TestTag {
	re := regexp.MustCompile(`%%([0-9]+)(.*?)/(.*?)/(.*?)\(([a-zA-Z]{1})\)`)

	match := re.FindStringSubmatch(s)

	if len(match) == 6 {
		dd, _ := strconv.Atoi(match[1])
		severity, _ := strconv.Atoi(match[3])
		return &TestTag{
			DD:       dd,
			Module:   match[2],
			Severity: severity,
			Brief:    match[4],
			LogType:  match[5],
		}
	}
	return nil
}

func parserContent(s string) *TestContent {
	array := make([]string, 0)
	content := TestContent{}
	reflect.ValueOf(&content)
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
		return nil
	}

	return &content
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
	parser := rfc3164.NewParser[TestTag, TestContent]()
	parser.WithTimestampFormat("2006-01-02 15:04:05")
	parser.WithTagFunc(parserTag)
	parser.WithContentFunc(parserContent)
	if err := parser.Parse(testLog); err != nil {
		log.Fatal(err.Error())
	}

	result := parser.Dump()
	fmt.Println(result.Tag.(*TestTag))
	fmt.Println(result.Content.(*TestContent))
}
