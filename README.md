# SEIM_Query 
<img src="https://img.shields.io/badge/SIEM-Security_Information_Event_Management-blue"/> <img src="https://img.shields.io/badge/splunk-000000.svg" /> 
Splunk siem query collection

[NAC query](#nac-query)
[UTM query](#utm-query)
[AntiVirus query](#antivirus-query)
[Running Status query](#running-status-query)


# NAC Query
<img src="https://img.shields.io/badge/NAC-Network_Access_Control-green"/> <img src="https://img.shields.io/badge/genian-000000.svg" />
```
'comment(Unmanaged Node)'

index="nac" "*비관리노드*"
'comment(Extract Specific logs by string)'

'comment(Extract Fields)'

| rex field = sensor "\((?<output>.+)\)"
'comment(Extract the sensor ip which is located between () from sensor sourcetype)'
| rex field = ouput "^(?<sensor_ab>\d{1,3}+\.\d{1,3})"
'comment(Extract 1st,2st Octet from sensor ip)'
| rex field = "단말IP" "^(?<ip_ab>\d{1,3}+\.\d{1,3})"
'comment(Extract 1st,2st Octet from terminal Ip addr)'
| rex field="단말MAC" "^(?<mac_abc>\w{1,2}+\:\w{1,2}+\:\w{1,2})"
'comment(Extract 1st,2st,3st Octet from terminal Mac addr)'


'comment(예외처리 / Exception Handling)'

| search NOT ip="x.x.x.x"
'comment(Except identified equip(printer, network equip,..)'s Ip addr)'
| search NOT MAC="x.x.x.x.x.x"
'comment(Except identified equip(printer, network equip,..)'s Mac addr)'
| search NOT ip_ab="x.x"
'comment(Except identified equip(printer, network equip,..)'s Ip addr band)'
| search NOT mac_abc="x:x:x"
'comment(Except identified equip(printer, network equip,..)'s Mac addr band)'

'comment(Visualization)'
| table 탐지시각,sensor,단말MAC,단말IP
| appendpip [stats count | eval ip=" " | where count==0 | fields - count]


'comment(unmanged/no lan equip, unmanged SW -> Extract by specific String)'
```

# AntiVirus Query 
<img src="https://img.shields.io/badge/Virus_Management-Anti_Virus-%23ba8cde"/> <img src="https://img.shields.io/badge/ahnlab-000000.svg" />
```
index="virus"

| eval status=
CASE(
 status xxx, "치료완료",
 status xxx, "치료불가",
 status xxx, "치료 중",
 status xxx, "탐지",
...
)
'comment(Check Detection, In treatment, Completed,.. by status code val)'


| eval 정오탐 =
CASE(
match(name,"예외처리바이러스명"),"예외처리",
match(name,"예외처리바이러스명2"),"예외처리",
match(file_hash,"예외처리바이러스해시값"),"예외처리",
...
)
'comment(Handling Exception lists by virus name, hash val)'



| table 상태, 탐지시각, IP, 정오탐, 바이러스명, 경로
} dedup 탐지시각
'comment(Except duplicate time logs)'


| appendpip [stats count | eval ip=" " | where count==0 | fields - count]
```


# UTM Query 
<img src="https://img.shields.io/badge/UTM-Unified_Threat_Management-%2311faf2"/> <img src="https://img.shields.io/badge/ahnlab-000000.svg" />
```
'comment(Scan Detection)'

| tstats c where index IN (UTM) by src_ip, dest_ip, dest_port
'comment(sort utm log by src_ip, dest_ip, dest_port)'
| rex field = src_ip "^(?<src_ip_abc>\d{1,3}+\.\d{1,3}+\.\d{1,3})"
| rex field = dest_ip "^(?<dest_ip_abc>\d{1,3}+\.\d{1,3}+\.\d{1,3})"
'comment(Extract src_ip, dest_ip에서 up to 3rd band)'
| stats c dc(dest_ip) as dc_dip dc(dest_port) as dc_port values(dest_port) by src_ip dest_ip abc
'comment(Search dest_ip, dest_port based on src_ip, dest_ip band)'
| where dc_dip >?? AND dc_port < ?
'comment(Search for destination IPs with more than ?? and destination PORTs with less than ??)'
|table src_ip, d_ip_abc, dc_dip, dc_port



'comment(Data Leak Detection)'

index IN (UTM) sourcetype IN (*allow*)
'comment(Check allow logs)'
| eval 탐지시각 = strftime(_time,"%Y/%m/%d %H:%M:%S")
| stats sum(sent_data) as sd, sum(rcvd_data) as rd by src_ip, dest_ip, protocol, dest_port, 탐지시각
'comment(Extract Sent Data, Received Data based on src_ip, dest_ip, protocol, dest_port, time)'
| rex field = src_ip "^(<srcrange>\d+\.\d|\.)"
| rex field = dest_ip "^(<destrange>\d+\.\d|\.)"
| where srcrange != destrange
'comment(Extract src_ip /dest ip band and exept same band)'
| eval sd_M=round(sd/1,2), rd_M=round(rd/1,2)
'comment(가시성을 위하여 round 함수 사용(round 함수 : 소수점 제거 및 반올림 함수))'
| eval sd_M=sd_M/1000000, rd_M=rd_M/1000000
'comment(chagne bit to mega)'
| eval traffic=sd_M+rd_M
| where sd_M > 100
'comment(Extract when sent_data is more then ??)'
| table 탐지시각, src_ip, dest_ip, rd_M, sd_M, traffic
| appendpipe [stats count | eval ip=" "| where count==0 | fields - count ]


'comment(Admin connection ip)'

index = UTM "*ADMIN*" host=x.x.x.x
'comment(Extract log based on string(ADMIN))'
| eval 탐지시각 = strftime(_time,"%Y/%m/%d %H:%M:%S")
| rename src_ip as 접속지
| dedup 접속지
'comment(Remove duplicate connection ip)'
| table 접속지, 탐지시각
| appendpipe [stats count | eval ip=" "| where count==0 | fields - count ]
```

'comment(트래픽 분석/ Traffic Analysis)'

| tstats count where index=UTM host=x.x.x.x by _time, sourcetype
| timechart sum(count) by sourcetype
'comment(time chart를 이용하여 utm traffic sourcetype(allow,deny) 시각화)'
'comment(visualization utm traffic(allow, deny) using by time chart )


# Running Status Query
```
index="Equipment to check"
| stats dc(_time) as stauses by host
| eval changed(statuses>1,"ON","OFF")
| table changed
'comment(Check running status based on time section)'

index="Equipment to check"
| stats by sourcetype
| stats count
| eval changed(count>1,"ON","확인필요")
| table changed
'comment(If there is only 1 sourcetype from log, Check)
'comment(Identify the problem that the virus-linked server periodically transmits only the syslog source type 
/ Logs such as malware infection information and administrator events must also be output.)'
```
