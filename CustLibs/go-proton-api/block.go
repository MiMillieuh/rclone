package proton

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"time"

	"github.com/go-resty/resty/v2"
)

func (c *Client) GetBlock(ctx context.Context, bareURL, token string) (io.ReadCloser, error) {
	res, err := c.doRes(ctx, func(r *resty.Request) (*resty.Response, error) {
		return r.SetHeader("pm-storage-token", token).SetDoNotParseResponse(true).Get(bareURL)
	})
	if err != nil {
		return nil, err
	}

	return res.RawBody(), nil
}

func (c *Client) RequestBlockUpload(ctx context.Context, req BlockUploadReq) ([]BlockUploadLink, error) {
	var res struct {
		UploadLinks []BlockUploadLink
	}

	if err := c.do(ctx, func(r *resty.Request) (*resty.Response, error) {
		return r.SetResult(&res).SetBody(req).Post("/drive/blocks")
	}); err != nil {
		return nil, err
	}

	return res.UploadLinks, nil
}

func (c *Client) UploadBlock(ctx context.Context, bareURL, token string, block io.Reader) error {
	var lastErr error
	data, err := io.ReadAll(block)
	if err != nil {
		return err
	}

	for attempt := 0; attempt < 10; attempt++ {
		if attempt > 0 {
			// jittered exponential backoff
			sleepTime := time.Duration(attempt*attempt)*time.Second + time.Duration(rand.Intn(1000))*time.Millisecond
			timer := time.NewTimer(sleepTime)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}

		// Use a clean request with its own client to ensure no inherited auth/cookies
		cl := resty.New()
		cl.SetTimeout(time.Minute * 10) // Increase timeout for large blocks/slow nodes
		
		res, err := cl.R().
			SetContext(ctx).
			SetHeader("pm-storage-token", token).
			SetHeader("Cache-Control", "no-cache, no-store, max-age=0").
			SetHeader("x-pm-appversion", "web-drive@5.0.35").
			SetHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36").
			SetMultipartField("Block", "Block", "application/octet-stream", bytes.NewReader(data)).
			Post(bareURL)

		if err == nil {
			if res.IsError() {
				lastErr = fmt.Errorf("storage node error: %s (%d)", res.Status(), res.StatusCode())
				// Retry on transient server errors (5xx) or rate limits (429) or specific 422s
				if res.StatusCode() >= 500 || res.StatusCode() == 429 || res.StatusCode() == 422 {
					continue
				}
				return lastErr
			}
			return nil
		}

		lastErr = err
		// Retry on network errors
		continue
	}

	return fmt.Errorf("failed to upload block after 10 attempts: %w", lastErr)
}
