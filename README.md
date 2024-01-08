# SEIM_query
Splunk siem query collection

# NAC query
```spl
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
