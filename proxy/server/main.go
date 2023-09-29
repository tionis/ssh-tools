package server

import (
	"context"
	"fmt"
	"github.com/go-fed/httpsig"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	//"github.com/jbowes/httpsig"
	"golang.org/x/crypto/ssh"
	"io"
	"log/slog"
	"net"
	"net/http"
	"tasadar.net/tionis/ssh-tools/proxy/lib"
	"time"
)

const (
	dialTimeout  = 10 * time.Second
	writeTimeout = 10 * time.Second
	readTimeout  = 10 * time.Second
)

type Server struct {
	address    string
	authKeys   map[string]ssh.PublicKey
	log        *slog.Logger
	httpServ   *http.Server
	listenPath string
}

func New(logger *slog.Logger, listenPath string, authorizedKeys []ssh.PublicKey, address string) (*Server, error) {
	var authKeyMap map[string]ssh.PublicKey
	for _, key := range authorizedKeys {
		authKeyMap[string(key.Marshal())] = key
	}
	s := &Server{
		address:    address,
		authKeys:   authKeyMap,
		log:        logger,
		listenPath: listenPath,
	}
	upgrader := websocket.Upgrader{
		ReadBufferSize:   1024,
		WriteBufferSize:  1024,
		HandshakeTimeout: 10 * time.Second,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handleProxy(upgrader, w, r)
	})

	m := mux.NewRouter()
	if listenPath != "" {
		m.Handle(fmt.Sprintf("/%s/{host}/{port}", listenPath), handler)
	} else {
		m.Handle("/{host}/{port}", handler)
	}

	s.httpServ = &http.Server{
		Addr:           s.address,
		Handler:        m,
		ReadTimeout:    readTimeout,
		WriteTimeout:   writeTimeout,
		MaxHeaderBytes: 1 << 20,
	}
	return s, nil
}

func (s *Server) Start() error {
	return s.httpServ.ListenAndServe()
}

func sshKeyTypeToHTTPSigType(sshKeyType string) httpsig.Algorithm {
	// TODO do the key type conversion here
	fmt.Printf("sshKeyType: %s", sshKeyType)
	return httpsig.ECDSA_SHA384
}

func (s *Server) VerifyRequest(r *http.Request) error {
	verifier, err := httpsig.NewVerifier(r)
	if err != nil {
		s.log.Error("Failed to create verifier", "error", err)
		return err
	}
	keyID := verifier.KeyId()
	if key, ok := s.authKeys[keyID]; !ok {
		// TODO test if this actually works
		return verifier.Verify(key, sshKeyTypeToHTTPSigType(key.Type()))
	} else {
		s.log.Error("Key ID not found", "keyID", keyID)
		return fmt.Errorf("key ID not found")
	}
}

func (s *Server) handleProxy(upgrader websocket.Upgrader, w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	err := s.VerifyRequest(r)
	if err != nil {
		s.log.Error("Failed to verify request", "error", err)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("403 - Access forbidden"))
		return
	}

	vars := mux.Vars(r)
	host := vars["host"]
	port := vars["port"]

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.log.Warn("Failed to upgrade to websockets", "error", err)
		return
	}
	defer conn.Close()

	conn2, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), dialTimeout)
	if err != nil {
		s.log.Warn("Failed to connect", "host", host, "port", port, "error", err)
		return
	}
	defer conn2.Close()

	// websocket -> server
	go func() {
		for {
			mt, r, err := conn.NextReader()
			if websocket.IsCloseError(err,
				websocket.CloseNormalClosure,   // Normal.
				websocket.CloseAbnormalClosure, // OpenSSH killed proxy client.
			) {
				return
			}
			if err != nil {
				s.log.Error("nextreader:", "error", err)
				return
			}
			if mt != websocket.BinaryMessage {
				s.log.Error("received non-binary websocket message")
				return
			}
			if _, err := io.Copy(conn2, r); err != nil {
				s.log.Warn("Reading from websocket", "error", err)
				cancel()
			}
		}
	}()

	// server -> websocket
	// TODO: NextWriter() seems to be broken.
	if err := lib.File2WS(s.log, ctx, cancel, conn2, conn); err == io.EOF {
		if err := conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(writeTimeout)); err == websocket.ErrCloseSent {
		} else if err != nil {
			s.log.Warn("Error sending close message:", "error", err)
		}
	} else if err != nil {
		s.log.Warn("Reading from file: %v", "error", err)
	}
}
