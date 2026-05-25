// Reference purple-wolf-relay subscriber in Go (net/http).
//
// Build & run:
//   PURPLEWOLF_SECRET=$(openssl rand -hex 32) go run go.go
//
// Verifies the HMAC, checks timestamp skew (replay protection),
// dedupes on event_id, responds 200 on success.

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	secret = []byte(os.Getenv("PURPLEWOLF_SECRET"))
	seen   sync.Map
	skew   = 300 * time.Second
)

func receive(w http.ResponseWriter, r *http.Request) {
	tsHdr := r.Header.Get("X-PurpleWolf-Timestamp")
	sig := r.Header.Get("X-PurpleWolf-Signature")
	eid := r.Header.Get("X-PurpleWolf-Event-Id")
	if tsHdr == "" || !strings.HasPrefix(sig, "sha256=") || eid == "" {
		http.Error(w, "bad headers", http.StatusBadRequest)
		return
	}
	ts, err := strconv.ParseInt(tsHdr, 10, 64)
	if err != nil {
		http.Error(w, "bad ts", http.StatusBadRequest)
		return
	}
	if abs(time.Now().Unix()-ts) > int64(skew.Seconds()) {
		http.Error(w, "skew", http.StatusUnauthorized)
		return
	}
	body, _ := io.ReadAll(r.Body)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(strconv.FormatInt(ts, 10) + "."))
	mac.Write(body)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(sig)) {
		http.Error(w, "sig", http.StatusUnauthorized)
		return
	}
	if _, dup := seen.LoadOrStore(eid, time.Now()); dup {
		w.WriteHeader(http.StatusOK)
		return
	}
	log.Printf("delivery %s: %s", eid, body)
	w.WriteHeader(http.StatusOK)
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func main() {
	http.HandleFunc("/webhook", receive)
	log.Println("listening on :8080")
	_ = http.ListenAndServe(":8080", nil)
}
