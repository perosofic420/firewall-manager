package cloudflare

import (
	"io"
	"fmt"
	"time"
	"strings"
	"net/http"
	"encoding/json/v2"
)

func GetV4IPs() ([]string, error) {
	req, err := http.NewRequest("GET", "https://www.cloudflare.com/ips-v4", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for Cloudflare V4 IPs: %w", err)
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request V4 IPs from Cloudflare: %w", err)
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Cloudflare V4 IP response: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get V4 IPs from Cloudflare (%d): %s", res.StatusCode, string(resBody))
	}

	v4IPs := strings.Fields(string(resBody))
	return v4IPs, nil
}

func GetV6IPs() ([]string, error) {
	req, err := http.NewRequest("GET", "https://www.cloudflare.com/ips-v6", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to request V6 IPs from Cloudflare")
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request V4 IPs from Cloudflare: %w", err)
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Cloudflare V4 IP response: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get V4 IPs from Cloudflare (%d): %s", res.StatusCode, string(resBody))
	}

	v6IPs := strings.Fields(string(resBody))
	return v6IPs, nil
}

func GetFallbackV4IPs() ([]string, error) {
	req, err := http.NewRequest("GET", "https://cdn.perosofic.dev/cloudflare-v4.json", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to request Cloudflare V4 IPs from backup")
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 15 * time.Second,
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("failed to get Cloudflare V4 IPs from backup (%d): %s", res.StatusCode, string(resBody))
	}

	var v4IPs []string
	if err := json.Unmarshal(resBody, &v4IPs, json.MatchCaseInsensitiveNames(true)); err != nil {
		return nil, fmt.Errorf("failed to parse response for Cloudflare V4 IPs from backup: %w", err)
	}

	return v4IPs, nil
}

func GetFallbackV6IPs() ([]string, error) {
	req, err := http.NewRequest("GET", "https://cdn.perosofic.dev/cloudflare-v6.json", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to request Cloudflare V6 IPs from backup")
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 15 * time.Second,
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("failed to get Cloudflare V6 IPs from backup (%d): %s", res.StatusCode, string(resBody))
	}

	var v6IPs []string
	if err := json.Unmarshal(resBody, &v6IPs, json.MatchCaseInsensitiveNames(true)); err != nil {
		return nil, fmt.Errorf("failed to parse response for Cloudflare V6 IPs from backup: %w", err)
	}

	return v6IPs, nil
}
