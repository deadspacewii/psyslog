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

var testLog = `<189>2023-08-07 09:28:26 192.168.11.1 %%01SEC/5/ATCKDF(l):log_type=ip_attack_alarm alarm_id=-7338214038077298709 device_ip=192.168.11.1 device_type=CLEAN direction=inbound zone_id=90 zone_name=hidef_59_56_77_212 zone_ip=59.56.77.212 start_time="2023-08-07 09:17:02" refresh_time="2023-08-07 09:28:26" severity=3 attack_type="SYN Flood,Single IP Bandwidth Overflow" attacker_ip="" in_pps=35154 in_bps=21548000 drop_pps=35148 drop_bps=21545000 max_in_pps=86784 max_in_bps=53320000 max_drop_pps=86784 max_drop_bps=53320000 forward_pps=6 forward_bps=3000 attack_status=NORMAL`

type TestTag struct {
	DD       int    `json:"dd"`
	Module   string `json:"module"`
	Severity int    `json:"severity"`
	Brief    string `json:"brief"`
	LogType  string `json:"LogType"`
}

type TestContent struct {
	LogType          string `json:"log_type"`
	Time             string `json:"time"`
	DeviceIp         string `json:"device_ip"`
	DeviceType       string `json:"device_type"`
	Direction        string `json:"direction"`
	ZoneId           int    `json:"zone_id"`
	ZoneName         string `json:"zone_name"`
	ZoneIp           string `json:"zone_ip"`
	BizId            int    `json:"biz_id"`
	IsDeszone        bool   `json:"is_deszone"`
	IsIpLocation     bool   `json:"is_ipLocation"`
	IpLocationId     int    `json:"ipLocation_id"`
	TotalPps         int    `json:"total_pps"`
	TotalKbps        int    `json:"total_kbps"`
	TcpPps           int    `json:"tcp_pps"`
	TcpKbps          int    `json:"tcp_kbps"`
	TcpfragPps       int    `json:"tcpfrag_pps"`
	TcpfragKbps      int    `json:"tcpfrag_kbps"`
	UdpPps           int    `json:"udp_pps"`
	UdpKbps          int    `json:"udp_kbps"`
	UdpfragPps       int    `json:"udpfrag_pps"`
	UdpfragKbps      int    `json:"udpfrag_kbps"`
	IcmpPps          int    `json:"icmp_pps"`
	IcmpKbps         int    `json:"icmp_kbps"`
	OtherPps         int    `json:"other_pps"`
	OtherKbps        int    `json:"other_kbps"`
	SynPps           int    `json:"syn_pps"`
	SynackPps        int    `json:"synack_pps"`
	AckPps           int    `json:"ack_pps"`
	FinrstPps        int    `json:"finrst_pps"`
	HttpPps          int    `json:"http_pps"`
	HttpKbps         int    `json:"http_kbps"`
	HttpGetPps       int    `json:"http_get_pps"`
	HttpsPps         int    `json:"https_pps"`
	HttpsKbps        int    `json:"https_kbps"`
	DnsRequestPps    int    `json:"dns_request_pps"`
	DnsRequestKbps   int    `json:"dns_request_kbps"`
	DnsReplyPps      int    `json:"dns_reply_pps"`
	DnsReplyKbps     int    `json:"dns_reply_kbps"`
	SipInvitePps     int    `json:"sip_invite_pps"`
	SipInviteKbps    int    `json:"sip_invite_kbps"`
	TotalAveragePps  int    `json:"total_average_pps"`
	TotalAverageKbps int    `json:"total_average_kbps"`
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

func parserContentWithStack(s string) map[string]any {
	s = strings.TrimSpace(s)
	var (
		mp         = make(map[string]any)
		key, value string
		isAll      bool
		length     = len(s)
	)

	for first, last := 0, 0; last < length; last++ {
		if s[last] == ' ' || last == length-1 {
			if !isAll || last == length-1 {
				if last == length-1 {
					value = strings.ReplaceAll(s[first:last+1], "\"", "")
				} else {
					value = strings.ReplaceAll(s[first:last], "\"", "")
				}
				num, err := strconv.Atoi(value)
				if err != nil {
					mp[key] = value
				} else {
					mp[key] = num
				}
				last++
				first = last
			}

			if last >= length {
				break
			}
		}

		if s[last] == '=' {
			key = strings.TrimSpace(s[first:last])
			last++
			first = last
		}

		if s[last] == '"' {
			isAll = !isAll
		}
	}

	return mp
}

func parserContent(s string) (TestContent, error) {
	array := make([]string, 0)
	content := TestContent{}
	reflect.ValueOf(&content)
	re := regexp.MustCompile(` .*?=".*?" `)

	match := re.FindAllString(s, -1)

	for _, item := range match {
		item = strings.TrimSpace(item)
		array = append(array, item)
		s = strings.ReplaceAll(s, item, "")
	}

	re = regexp.MustCompile(`(.*?=.*? )`)
	match = re.FindAllString(s, -1)

	array = append(array, strings.TrimSpace(s))
	jsonStr := parserValue2Json(array)
	if err := json.Unmarshal([]byte(jsonStr), &content); err != nil {
		return content, err
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
	parser := rfc3164.NewParser[TestTag, TestContent]()
	parser.WithTimestampFormat("2006-01-02 15:04:05")
	//parser.WithTagFunc(parserTag)
	parser.WithContentFunc(parserContent)
	if err := parser.Parse(testLog); err != nil {
		log.Fatal(err.Error())
	}

	result := parser.Dump()

	fmt.Println(result.ContentError)
}
