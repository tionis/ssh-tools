package lib

import (
	"context"
	"io"
	"log/slog"

	"github.com/gorilla/websocket"
)

// File2WS copies everything from the reader into the websocket,
// stopping on error or context cancellation.
func File2WS(log *slog.Logger, ctx context.Context, cancel func(), src io.Reader, dst *websocket.Conn) error {
	defer cancel()
	for {
		if ctx.Err() != nil {
			return nil
		}
		b := make([]byte, 32*1024)
		if n, err := src.Read(b); err != nil {
			return err
		} else {
			b = b[:n]
		}
		//log.Printf("->ws %d bytes: %q", len(b), string(b))
		if err := dst.WriteMessage(websocket.BinaryMessage, b); err != nil {
			log.Warn("Writing websockt message:", "error", err)
			return err
		}
	}
}
