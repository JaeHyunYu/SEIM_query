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
'comment(status 코드 값을 기준으로 바이러스 탐지, 치료 중, 치료불가, 치료완료 판별)'


| eval 정오탐 =
CASE(
match(name,"예외처리바이러스명"),"예외처리",
match(name,"예외처리바이러스명2"),"예외처리",
match(file_hash,"예외처리바이러스해시값"),"예외처리",
...
)
'comment(예외처리 virus들을 이름 및 파일 해시값을 기준으로 판별)'



| table 상태, 탐지시각, IP, 정오탐, 바이러스명, 경로
} dedup 탐지시각
'comment(겹치는 로그 제외)'


| appendpip [stats count | eval ip=" " | where count==0 | fields - count]
```


# Running Status query
```
index="확인할 장비명"
| stats dc(_time) as stauses by host
| eval changed(statuses>1,"ON","OFF")
| table changed
'comment(로그의 시간값을 기준으로 장비가동상태 확인)'

index="확인할 장비명"
| stats by sourcetype
| stats count
| eval changed(count>1,"ON","확인필요")
| table changed
'comment(sourcetype을 기준으로 1종류만 나올 시, 확인요청)'
'comment(바이러스 연동서버가 주기적으로 syslog sourcetype만 전송하는 문제 식별 / 악성코드 감염정보, 관리자 이벤트 등의 로그도 출력되야함)'
```
