package assembler

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"ligmashark/internal/types"
)

type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	httpEvents     chan<- types.HTTPInfo
}

func (h *httpStream) Reassembled(reassembly []tcpassembly.Reassembly) {
	h.r.Reassembled(reassembly)
}

func (h *httpStream) ReassemblyComplete() {
	reader := bufio.NewReader(&h.r)
	for {
		req, err := http.ReadRequest(reader)
		if err == io.EOF {
			return 
		}
		if err != nil {
			return
		}

		headers := make(map[string]string)
		for k, v := range req.Header {
			headers[k] = strings.Join(v, ", ")
		}

		url := req.URL.String()
		if !req.URL.IsAbs() {
			if host := req.Host; host != "" {
				scheme := "http" 
				if h.transport.Dst().String() == "443" {
					scheme = "https"
				}
				url = fmt.Sprintf("%s://%s%s", scheme, host, req.URL.Path)
				if req.URL.RawQuery != "" {
					url += "?" + req.URL.RawQuery
				}
			}
		}

		h.httpEvents <- types.HTTPInfo{
			Timestamp:   time.Now(),
			SrcIP:       h.net.Src().String(),
			DstIP:       h.net.Dst().String(),
			SrcPort:     h.transport.Src().String(),
			DstPort:     h.transport.Dst().String(),
			Protocol:    "HTTP",
			Length:      int(req.ContentLength), 
			URL:         url,
			HTTPMethod:  req.Method,
			HTTPHeaders: headers,
		}
	}
}

type HTTPStreamFactory struct {
	httpEvents chan<- types.HTTPInfo
}

func NewHTTPStreamFactory(httpEvents chan<- types.HTTPInfo) *HTTPStreamFactory {
	return &HTTPStreamFactory{
		httpEvents: httpEvents,
	}
}

func (f *HTTPStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	s := &httpStream{
		net:        net,
		transport:  transport,
		r:          tcpreader.NewReaderStream(),
		httpEvents: f.httpEvents,
	}

	go s.run()
	return s
}

func (s *httpStream) run() {
	defer func() {
		if s.transport.Dst().String() == "443" || s.transport.Src().String() == "443" {
			s.httpEvents <- types.HTTPInfo{
				Timestamp: time.Now(),
				SrcIP:     s.net.Src().String(),
				DstIP:     s.net.Dst().String(),
				SrcPort:   s.transport.Src().String(),
				DstPort:   s.transport.Dst().String(),
				Protocol:  "HTTPS",
				URL:       fmt.Sprintf("https://%s", s.net.Dst().String()), 
			}
		}
		io.Copy(io.Discard, &s.r)
	}()

}