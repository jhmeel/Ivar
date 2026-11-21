// Package coreclient delivers events to the IVAR core ingest gateway. It
// buffers while the core is unreachable, drops the oldest beyond capacity
// (reported to the core as a gap), and sends a heartbeat so silence raises a
// tamper alert within 60 seconds.
package coreclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ivar/ivar/go/internal/ocsf"
)

// Client sends batches to POST {core}/v1/events.
type Client struct {
	URL        string
	SensorID   string
	SensorType string
	HTTP       *http.Client
	Capacity   int

	mu      sync.Mutex
	buf     []ocsf.Event
	dropped int
	// OnVerdicts receives verdicts returned by the core.
	OnVerdicts func([]map[string]any)
}

// New returns a client with sensible defaults.
func New(url, sensorID, sensorType string) *Client {
	return &Client{URL: strings.TrimRight(url, "/"), SensorID: sensorID, SensorType: sensorType, HTTP: &http.Client{Timeout: 5 * time.Second}, Capacity: 50_000}
}

// Emit queues one event.
func (c *Client) Emit(e ocsf.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.buf) >= c.Capacity {
		c.buf = c.buf[1:]
		c.dropped++
	}
	c.buf = append(c.buf, e)
}

// Pending reports queued and dropped counts.
func (c *Client) Pending() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.buf), c.dropped
}

// Flush sends everything queued; on failure the events stay queued.
func (c *Client) Flush(ctx context.Context) error {
	c.mu.Lock()
	batch := c.buf
	c.buf = nil
	dropped := c.dropped
	c.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	body, _ := json.Marshal(map[string]any{"sensor_id": c.SensorID, "dropped": dropped, "events": batch})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/v1/events", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err == nil && resp.StatusCode >= 300 {
		err = fmt.Errorf("core returned %d", resp.StatusCode)
	}
	if err != nil {
		c.mu.Lock()
		c.buf = append(batch, c.buf...)
		c.mu.Unlock()
		return err
	}
	defer resp.Body.Close()
	var ack struct {
		Verdicts []map[string]any `json:"verdicts"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&ack)
	c.mu.Lock()
	c.dropped = 0
	c.mu.Unlock()
	if c.OnVerdicts != nil && len(ack.Verdicts) > 0 {
		c.OnVerdicts(ack.Verdicts)
	}
	return nil
}

// Run flushes every interval and sends heartbeats until ctx ends.
func (c *Client) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	hb := time.NewTicker(20 * time.Second)
	defer t.Stop()
	defer hb.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = c.Flush(context.Background())
			return
		case <-hb.C:
			c.Emit(ocsf.New(c.SensorID, c.SensorType, 0, "sensor.heartbeat", time.Now()))
		case <-t.C:
			_ = c.Flush(ctx)
		}
	}
}
