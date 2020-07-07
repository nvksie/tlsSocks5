package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
)

type clientConfig struct {
	Remote         string `json:"remote"`
	Local          string `json:"local"`
	Servername     string `json:"servername"`
	SkipVerifyCert bool   `json:"skipVerifyCert"`
	Username       string `json:"username"`
	Password       string `json:"password"`
}

func (cfg *clientConfig) Init() {
	cfg.Remote = "127.0.0.1:8443"
	cfg.Local = "127.0.0.1:10086"
	cfg.Servername = "example.com"
	cfg.SkipVerifyCert = false
	cfg.Username = ""
	cfg.Password = ""
}

func (cfg *clientConfig) Load(file string) {
	log.Printf("read configuration from file: '%s' ... ", file)
	content, err := ioutil.ReadFile(file)
	if err != nil {
		log.Panicln(err)
	}
	err = json.Unmarshal(content, cfg)
	if err != nil {
		log.Panicln(err)
	}
}

func (cfg *clientConfig) Write(file string) {
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
	var configFile = flag.String("config", "client_config.json", "configuration file")
	var newConfig = flag.Bool("newConfig", false, "write new default config to the file specified by '-config'")
	flag.Parse()
	cfg := new(clientConfig)
	if *newConfig {
		cfg.Init()
		cfg.Write(*configFile)
		return
	}
	cfg.Load(*configFile)

	ln, err := net.Listen("tcp", cfg.Local)
	if err != nil {
		panic(err)
	}

	sysCertPool, err := x509.SystemCertPool()
	if err != nil {
		panic(err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		log.Printf("new connection from %s", conn.RemoteAddr().String())
		// TODO: 加链接复用
		// TODO: 加http代理端口
		go func(conn net.Conn, remote string) {
			defer conn.Close()
			rconn, err := tls.Dial("tcp", remote, &tls.Config{RootCAs: sysCertPool, ServerName: cfg.Servername, InsecureSkipVerify: cfg.SkipVerifyCert})
			if err != nil {
				log.Println(err)
				return
			}
			defer rconn.Close()
			if overrideClientAuth(conn, rconn, cfg) {
				transfer(conn, rconn)
			}
		}(conn, cfg.Remote)
	}
}

func overrideClientAuth(client, server net.Conn, cfg *clientConfig) bool {
	var b [256]byte
	n, err := client.Read(b[:])
	if err != nil {
		log.Println(client.RemoteAddr().String(), err)
		return false
	}
	if n > 0 && b[0] == 0x05 { //Socks5协议
		server.Write([]byte{0x05, 0x01, 0x02}) // socks5 user:pass auth
		n, err := server.Read(b[:])
		if err != nil {
			log.Println(client.RemoteAddr().String(), err)
			return false
		}
		if n == 2 && b[0] == 0x05 && b[1] == 0x02 {
			content := make([]byte, 3+len(cfg.Username)+len(cfg.Password))
			idx := 0
			content[idx] = 0x01
			idx++
			content[idx] = byte(len(cfg.Username))
			idx++
			for _, c := range cfg.Username {
				content[idx] = byte(c)
				idx++
			}
			content[idx] = byte(len(cfg.Password))
			idx++
			for _, c := range cfg.Password {
				content[idx] = byte(c)
				idx++
			}
			server.Write(content)
			n, err := server.Read(b[:])
			if err != nil {
				log.Println(client.RemoteAddr().String(), err)
				return false
			}
			if n == 2 && b[0] == 0x01 && b[1] == 0x00 {
				client.Write([]byte{0x05, 0x00})
				return true
			}
		}
	}
	return false
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
