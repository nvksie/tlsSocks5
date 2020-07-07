package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	parseHeader = iota
	parseBody
)

const (
	bodyEOFContentLength = iota
	bodyEOFChunked
	bodyEOFWebsocket
)

func randSeq(n int) string {
	rand.Seed(time.Now().UnixNano())
	var letters = []rune("1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

type tlsCert struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

type userInfo struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type serverConfig struct {
	Listen        string            `json:"listen"`
	LocalHTTP     string            `json:"local_http"`
	Ipv6          bool              `json:"ipv6"`
	TLS           []tlsCert         `json:"tls"`
	Auth          []userInfo        `json:"auth"`
	UserPassPairs map[string]string `json:"-"`
}

func (cfg *serverConfig) Init() {
	cfg.Listen = "127.0.0.1:8443"
	cfg.LocalHTTP = "127.0.0.1:80"
	cfg.Ipv6 = false
	cfg.TLS = []tlsCert{{Cert: "default.crt", Key: "default.key"}}
	cfg.Auth = []userInfo{{Username: "user", Password: randSeq(16)}}
}

func (cfg *serverConfig) Load(file string) {
	log.Printf("read configuration from file: '%s' ... ", file)
	content, err := ioutil.ReadFile(file)
	if err != nil {
		log.Panicln(err)
	}
	err = json.Unmarshal(content, cfg)
	if err != nil {
		log.Panicln(err)
	}
	if len(cfg.Auth) < 1 {
		log.Panicln("auth info not found in configuration file")
	}
	cfg.UserPassPairs = map[string]string{}
	for _, userinfo := range cfg.Auth {
		cfg.UserPassPairs[userinfo.Username] = userinfo.Password
	}
}

func (cfg *serverConfig) Write(file string) {
	log.Printf("write configuration to file: '%s'", file)
	content, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		log.Panicln(err)
	}
	err = ioutil.WriteFile(file, content, 0644)
	if err != nil {
		log.Panicln(err)
	}
}

func main() {
	var configFile = flag.String("config", "server_config.json", "configuration file")
	var newConfig = flag.Bool("newConfig", false, "write new default config to the file specified by '-config'")
	flag.Parse()
	cfg := new(serverConfig)
	if *newConfig {
		cfg.Init()
		cfg.Write(*configFile)
		return
	}
	cfg.Load(*configFile)

	var certs []tls.Certificate
	for _, cert := range cfg.TLS {
		cer, err := tls.LoadX509KeyPair(cert.Cert, cert.Key)
		if err != nil {
			log.Panic(err)
		}
		certs = append(certs, cer)
	}
	ln, err := tls.Listen("tcp", cfg.Listen, &tls.Config{Certificates: certs})
	if err != nil {
		log.Panic(err)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		log.Printf("new connection from %s", conn.RemoteAddr().String())
		go handleClientRequest(conn, cfg)
	}
}

func handleClientRequest(conn net.Conn, cfg *serverConfig) {
	defer conn.Close()

	var b [256]byte
	n, err := conn.Read(b[:8])
	if err != nil {
		log.Println(conn.RemoteAddr().String(), err)
		return
	}

	// https://zh.wikipedia.org/wiki/SOCKS
	if n > 0 && b[0] == 0x05 { //Socks5协议
		found := false
		if int(b[1])+2 <= n {
			for i := 0; i < int(b[1]); i++ {
				if b[2+i] == 0x02 {
					found = true
					break
				}
			}
		}
		if !found {
			log.Printf("client[%s] no available auth method", conn.RemoteAddr().String())
			conn.Write([]byte{0x05, 0xff})
			return
		}
		//用户名、密码认证
		var user string
		conn.Write([]byte{0x05, 0x02})
		n, err = conn.Read(b[:])
		if n > 0 && b[0] == 0x01 {
			userlen := int(b[1])
			user = string(b[2 : 2+userlen])
			passlen := int(b[2+userlen])
			pass := string(b[3+userlen : 3+userlen+passlen])
			if sp, ok := cfg.UserPassPairs[user]; ok && sp == pass {
				log.Printf("client[%s] user '%s' auth success", conn.RemoteAddr().String(), user)
				conn.Write([]byte{0x01, 0x00})
			} else {
				log.Printf("client[%s] user '%s' auth failed", conn.RemoteAddr().String(), user)
				conn.Write([]byte{0x01, 0x01})
				return
			}
		} else {
			log.Printf("auth failed")
			conn.Write([]byte{0x01, 0x01})
			return
		}
		n, err = conn.Read(b[:])
		if n < 4 || b[1] != 0x01 || b[2] != 0x00 {
			log.Printf("socks5 unsupported req cmd from client[%s] user[%s]", conn.RemoteAddr().String(), user)
			conn.Write([]byte{0x05, 0x07})
			return
		}
		var host string
		var port int
		switch b[3] {
		case 0x01: // ipv4
			if n-2 <= 7 {
				conn.Write([]byte{0x05, 0x08})
				log.Printf("invalid ipv4 addr from client[%s] user[%s]", conn.RemoteAddr().String(), user)
				return
			}
			host = net.IPv4(b[4], b[5], b[6], b[7]).String()
		case 0x03: // domain
			if n-2 <= 5 || n-2-5 != int(b[4]) {
				conn.Write([]byte{0x05, 0x08})
				log.Printf("invalid domain addr from client[%s] user[%s]", conn.RemoteAddr().String(), user)
				return
			}
			host = string(b[5 : n-2]) //b[4]表示域名的长度
		case 0x04: // ipv6
			if n-2 <= 19 {
				conn.Write([]byte{0x05, 0x08})
				log.Printf("invalid ipv6 addr from client[%s] user[%s]", conn.RemoteAddr().String(), user)
				return
			}
			host = net.IP{b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19]}.String()
		default:
			conn.Write([]byte{0x05, 0x08})
			log.Printf("socks5 invalid addr type(0x%02x) from client[%s] user[%s]", b[3], conn.RemoteAddr().String(), user)
			return
		}
		port = int(b[n-2])<<8 | int(b[n-1])

		log.Printf("client[%s] user[%s] connect %s:%d", conn.RemoteAddr().String(), user, host, port)

		tcpProxy(conn, host, port, cfg.Ipv6, user)
		log.Printf("client[%s] user[%s] disconnect", conn.RemoteAddr().String(), user)
		return
	}

	// proxy local http
	httpProxy(conn, cfg.LocalHTTP, b[:n], cfg.Ipv6)
}

func httpProxy(conn net.Conn, localhttp string, proviousData []byte, useIPV6 bool) {
	tcpAddr, err := net.ResolveTCPAddr(func(useIPV6 bool) string {
		if useIPV6 {
			return "tcp"
		}
		return "tcp4"
	}(useIPV6), localhttp)
	if err != nil {
		log.Printf("client[%s] resolve [%s] error, %s", conn.RemoteAddr().String(), localhttp, err)
		return
	}
	log.Printf("client[%s] connect local http[%s] addr[%s]", conn.RemoteAddr().String(), localhttp, tcpAddr.String())
	tcpConn, err := tcpDial(nil, tcpAddr, 10*time.Second)
	if err != nil {
		log.Printf("client[%s] connect local http[%s] error, %s", conn.RemoteAddr().String(), localhttp, err)
		return
	}
	defer tcpConn.Close()
	tcpConn.SetNoDelay(true)
	proxyWithXFF(conn, tcpConn, proviousData, localhttp)
}

func proxyWithXFF(conn, tcpConn net.Conn, proviousData []byte, localhttp string) {
	go func() {
		io.Copy(conn, tcpConn)
	}()
	buf := bufio.NewReader(conn)
	linebuf := bytes.NewBuffer(proviousData)
	step := parseHeader
	var bodytype int
	contentLength := 0
	xffparsed := false
	for line, isPrefix, err := buf.ReadLine(); err == nil; line, isPrefix, err = buf.ReadLine() {
		linebuf.Write(line)
		if !isPrefix {
			line := linebuf.String()
			switch step {
			case parseHeader:
				if len(line) == 0 {
					step = parseBody
					if !xffparsed {
						tcpConn.Write([]byte(fmt.Sprintf("X-Forwarded-For: %s\r\n", strings.SplitN(conn.RemoteAddr().String(), ":", 2)[0])))
					}
					break
				}
				strs := strings.SplitN(line, ":", 2)
				if len(strs) == 2 {
					switch strings.ToLower(strs[0]) {
					case "content-length":
						bodytype = bodyEOFContentLength
						contentLength, _ = strconv.Atoi(strs[1])
					case "transfer-encoding":
						if strings.Contains(strs[1], "chunked") {
							bodytype = bodyEOFChunked
						}
					case "host":
						linebuf.Reset()
						linebuf.WriteString(fmt.Sprintf("Host: %s", strings.SplitN(localhttp, ":", 2)[0]))
					case "connection":
						if strings.Compare(strings.ToLower(strs[1]), "upgrade") == 0 {
							bodytype = bodyEOFWebsocket
						}
					case "x-forwarded-for":
						linebuf.WriteString(fmt.Sprintf(", %s", strings.SplitN(conn.RemoteAddr().String(), ":", 2)[0]))
						xffparsed = true
					}
				}
			case parseBody:
				switch bodytype {
				case bodyEOFContentLength:
					contentLength -= linebuf.Len()
					if contentLength <= 0 {
						step = parseHeader
						xffparsed = false
					}
				case bodyEOFChunked:
					if len(line) == 0 {
						step = parseHeader
						xffparsed = false
					}
				}
			}
			linebuf.WriteTo(tcpConn)
			tcpConn.Write([]byte{'\r', '\n'})
			if bodytype == bodyEOFWebsocket {
				io.Copy(tcpConn, buf)
				break
			}
			linebuf.Reset()
		}
	}
}

func tcpProxy(conn net.Conn, dstAddr string, dstPort int, useIPV6 bool, user string) {
	addr := fmt.Sprintf("%s:%d", dstAddr, dstPort)
	tcpAddr, err := net.ResolveTCPAddr(func(useIPV6 bool) string {
		if useIPV6 {
			return "tcp"
		}
		return "tcp4"
	}(useIPV6), addr)
	if err != nil {
		conn.Write([]byte{0x05, 0x03})
		return
	}
	log.Printf("client[%s] user[%s] connect host[%s] addr[%s]", conn.RemoteAddr().String(), user, addr, tcpAddr.String())
	tcpConn, err := tcpDial(nil, tcpAddr, 30*time.Second)
	if err != nil {
		log.Printf("client[%s] user[%s] %s", conn.RemoteAddr().String(), user, err)
		conn.Write([]byte{0x05, 0x03})
		return
	}
	defer tcpConn.Close()

	//conn.SetNoDelay(true)
	tcpConn.SetNoDelay(true)
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	transfer(tcpConn, conn)
}

func transfer(server, client net.Conn) {
	block := make(chan bool)
	go func() {
		io.Copy(client, server)
		block <- true
	}()
	go func() {
		io.Copy(server, client)
		block <- true
	}()
	<-block
}

func tcpDial(localAddr, remoteAddr *net.TCPAddr, timeout time.Duration) (*net.TCPConn, error) {
	returned := false
	ticker := time.NewTicker(timeout)
	defer ticker.Stop()

	type rst struct {
		tcn *net.TCPConn
		error
	}

	rstChan := make(chan *rst, 0)
	go func() {
		tcpConn, err := net.DialTCP("tcp", localAddr, remoteAddr)
		if err != nil {
			goto Finish
		} else if returned {
			tcpConn.Close()
			return
		}
	Finish:
		rstChan <- &rst{tcn: tcpConn, error: err}
	}()

	select {
	case <-ticker.C:
		returned = true
		return nil, errors.New("connect timeout")
	case result := <-rstChan:
		if result.error != nil {
			return nil, result.error
		}
		return result.tcn, nil
	}
}
