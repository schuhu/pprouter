# PPRouter

Proxy protocol router. Currently it routes based on SNI, in the future it should do so based on the destination it receives via tcp proxy protocol. 



## Commands

```
curl  -o /dev/null -s -w 'Total: %{time_total}s\n'  --connect-to httpbin.org:443:127.0.0.1:1106 https://httpbin.org/get
curl  -o /dev/null -s -w 'Total: %{time_total}s\n' https://httpbin.org/get


curl -o /dev/null -s -w 'Total: %{time_total}s\n' --connect-to g.co:443:127.0.0.1:1106 https://g.co
curl -o /dev/null -s -w 'Total: %{time_total}s\n' https://g.co

```
