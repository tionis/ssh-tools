package client

import (
	"context"
	"crypto/tls"
	"github.com/aus/proxyplease"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"tasadar.net/tionis/ssh-tools/proxy/lib"
	"time"
)

type Client struct {
	writeTimeout time.Duration
	sshSigner    ssh.Signer
	log          *slog.Logger
	tlsInsecure  bool
}

func New(log *slog.Logger, sshSigner ssh.Signer) (*Client, error) {
	return &Client{
		writeTimeout: 10 * time.Second,
		sshSigner:    sshSigner,
		log:          log,
		tlsInsecure:  false,
	}, nil
}

func (c *Client) Connect(url string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// TODO do httpsig signature here

	dialContext := proxyplease.NewDialContext(proxyplease.Proxy{})

	dialer := websocket.Dialer{
		// It's not documented if handshake timeout defaults.
		HandshakeTimeout: websocket.DefaultDialer.HandshakeTimeout,
		NetDialContext:   dialContext,
	}

	dialer.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: c.tlsInsecure,
	}
	head := map[string][]string{}

	conn, resp, err := dialer.Dial(url, head)
	if err != nil {
		c.dialError(url, resp, err)
	}
	defer conn.Close()

	// websocket -> stdout
	go func() {
		for {
			mt, r, err := conn.NextReader()
			if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
				return
			}
			if err != nil {
				log.Fatal(err)
			}
			if mt != websocket.BinaryMessage {
				log.Fatal("non-binary websocket message received")
			}
			if _, err := io.Copy(os.Stdout, r); err != nil {
				c.log.Error("Reading from websocket:", "error", err)
				cancel()
			}
		}
	}()

	// stdin -> websocket
	// TODO: NextWriter() seems to be broken.
	if err := lib.File2WS(c.log, ctx, cancel, os.Stdin, conn); err == io.EOF {
		if err := conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(c.writeTimeout)); err == websocket.ErrCloseSent {
		} else if err != nil {
			c.log.Error("Error sending 'close' message:", "error", err)
		}
	} else if err != nil {
		c.log.Error("reading from stdin:", "error", err)
		cancel()
	}

	return ctx.Err()
}

func (c *Client) dialError(url string, resp *http.Response, err error) {
	if resp != nil {
		extra := ""
		if c.log.Enabled(context.Background(), slog.LevelDebug) {
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				c.log.Warn("Failed to read HTTP body", "error", err)
			}
			extra = "Body:\n" + string(b)
		}
		log.Fatalf("%s: HTTP error: %d %s\n%s", err, resp.StatusCode, resp.Status, extra)

	}
	log.Fatalf("Dial to %q fail: %v", url, err)
}
