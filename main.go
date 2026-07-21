package main

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
)

const (
	TYPE_A    = 1
	TYPE_AAAA = 28
	CLASS_IN  = 1
)

const TTL uint32 = 60

var records = map[string]net.IP{}

func main() {
	data, err := os.ReadFile("records.ini")
	if err != nil {
		panic("failed to open records.ini")
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for _, line := range lines {
		parts := strings.Split(strings.TrimSpace(line), "=")
		ip := net.ParseIP(parts[1])
		if ip == nil {
			panic("failed to parse IP")
		}
		records[strings.ToLower(parts[0])] = ip
	}

	go func() {
		fmt.Println("Listening on :8053...")
		http.HandleFunc("/dns-query", handleHTTP)
		if err := http.ListenAndServe(":8053", nil); err != nil {
			panic(err)
		}
	}()

	addr, err := net.ResolveUDPAddr("udp", "0.0.0.0:53")
	if err != nil {
		panic(err)
	}
	listener, err := net.ListenUDP("udp", addr)
	if err != nil {
		panic(err)
	}

	fmt.Println("Listening on :53...")
	for {
		req := make([]byte, 4096)
		n, addr, err := listener.ReadFromUDP(req)
		if err != nil {
			fmt.Println("ERROR:", err)
			continue
		}

		go handleUDP(listener, req[:n], addr)
	}
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	var req []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		req, err = base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			http.Error(w, "invalid base64 encoding", http.StatusBadRequest)
			return
		}
	case http.MethodPost:
		req, err = io.ReadAll(io.LimitReader(r.Body, 65536))
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	resp := handleReq(ip, req)
	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

func handleUDP(listener *net.UDPConn, req []byte, addr *net.UDPAddr) {
	resp := handleReq(addr.IP.String(), req)
	if _, err := listener.WriteToUDP(resp, addr); err != nil {
		fmt.Println(err)
	}
}

func handleReq(ip string, req []byte) []byte {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Recovered from panic: CLIENT=%s: %v\n", ip, r)
		}
	}()

	// we assume that QDCOUNT=1 but i think that's reasonable

	// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
	// TODO: we should probably handle compression but from what i know clients don't generally use it
	labels := []string{}
	offset := 12
	for {
		length := int(req[offset])
		offset++
		if length == 0 || length > 63 {
			break
		}
		labels = append(labels, string(req[offset:offset+length]))
		offset += length
	}
	rawName := req[12:offset]
	name := strings.ToLower(strings.Join(labels, "."))

	// https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
	questionType := binary.BigEndian.Uint16(req[offset:])
	offset += 2
	// https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4
	questionClass := binary.BigEndian.Uint16(req[offset:])
	offset += 2

	fmt.Printf("CLIENT=%s QNAME=%s TYPE=%d CLASS=%d\n", ip, name, questionType, questionClass)

	resp := make([]byte, offset)
	copy(resp, req[:offset])

	resp[2] |= 0x80 // QR=1 (response)
	resp[3] &= 0xf0 // clear RCODE
	resp[2] |= 0x04 // authoritative answer
	resp[3] &= 0x7f // recursion not available

	binary.BigEndian.PutUint16(resp[6:], 0)  // ANCOUNT = 0
	binary.BigEndian.PutUint16(resp[8:], 0)  // NSCOUNT = 0
	binary.BigEndian.PutUint16(resp[10:], 0) // ARCOUNT = 0

	data := []byte{}
	if record, ok := records[name]; questionClass == CLASS_IN && ok {
		ip4 := record.To4()
		if questionType == TYPE_A && ip4 != nil {
			data = ip4
		} else if questionType == TYPE_AAAA && ip4 == nil {
			data = record
		}
	} else {
		resp[3] |= 0x03 // RCODE=NXDOMAIN
	}

	if len(data) > 0 {
		// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3
		resp = append(resp, rawName...)
		resp = binary.BigEndian.AppendUint16(resp, questionType)
		resp = binary.BigEndian.AppendUint16(resp, questionClass)
		resp = binary.BigEndian.AppendUint32(resp, TTL)
		resp = binary.BigEndian.AppendUint16(resp, uint16(len(data)))
		resp = append(resp, data...)

		binary.BigEndian.PutUint16(resp[6:], uint16(1)) // ANCOUNT=1
	}

	return resp
}
