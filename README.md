# SEIM_query
Splunk siem query collection

# NAC query
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

# AntiVirus query
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


# Running Status query
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
