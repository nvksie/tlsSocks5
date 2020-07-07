# tlsSocks5
socks5 over tls  
支持复用443端口，当判断为https流量时，转发到http web server  
支持多证书  
http转发时，会添加http header `X-Forwarded-For`，http web server可以取到客户端真实ip  
不支持udp转发

# 客户端
除了client.go，实测[shadowrocket](https://apps.apple.com/us/app/shadowrocket/id932747118)、[Quantumult](https://apps.apple.com/us/app/quantumult/id1252015438)可以兼容

# 如何用
server.go只有约500行代码  
直接`go build server.go`得到可执行程序server  
`./server -newConfig`可得默认配置文件  
然后配上地址端口、tls证书、auth用户名密码，执行即可  
客户端同理
