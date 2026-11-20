package bunny

import (
	"io"
	"fmt"
	"time"
	"net/http"
	"encoding/json/v2"
)

func GetV4IPs() ([]string, error) {
	req, err := http.NewRequest("GET", "https://bunnycdn.com/api/system/edgeserverlist", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to request V4 IPs from Bunny")
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
		return nil, fmt.Errorf("failed to get V4 IPs from Bunny (%d): %s", res.StatusCode, string(resBody))
	}

	var v4IPs []string
	if err := json.Unmarshal(resBody, &v4IPs, json.MatchCaseInsensitiveNames(true)); err != nil {
		return nil, fmt.Errorf("failed to parse response for V4 IPs from Bunny: %w", err)
	}

	return v4IPs, nil
}

func GetV6IPs() ([]string, error) {
	req, err := http.NewRequest("GET", "https://bunnycdn.com/api/system/edgeserverlist/IPv6", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to request V6 IPs from Bunny")
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
		return nil, fmt.Errorf("failed to get V6 IPs from Bunny (%d): %s", res.StatusCode, string(resBody))
	}

	var v6IPs []string
	if err := json.Unmarshal(resBody, &v6IPs, json.MatchCaseInsensitiveNames(true)); err != nil {
		return nil, fmt.Errorf("failed to parse response for V6 IPs from Bunny: %w", err)
	}

	return v6IPs, nil
}

func GetFallbackV4IPs() ([]string, error) {
	req, err := http.NewRequest("GET", "https://cdn.perosofic.dev/bunny-v4.json", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to request Bunny V4 IPs from backup")
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
		return nil, fmt.Errorf("failed to get Bunny V4 IPs from backup (%d): %s", res.StatusCode, string(resBody))
	}

	var v4IPs []string
	if err := json.Unmarshal(resBody, &v4IPs, json.MatchCaseInsensitiveNames(true)); err != nil {
		return nil, fmt.Errorf("failed to parse response for Bunny V4 IPs from backup: %w", err)
	}

	return v4IPs, nil
}

func GetFallbackV6IPs() ([]string, error) {
	req, err := http.NewRequest("GET", "https://cdn.perosofic.dev/bunny-v6.json", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to request Bunny V6 IPs from backup")
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
		return nil, fmt.Errorf("failed to get Bunny V6 IPs from backup (%d): %s", res.StatusCode, string(resBody))
	}

	var v6IPs []string
	if err := json.Unmarshal(resBody, &v6IPs, json.MatchCaseInsensitiveNames(true)); err != nil {
		return nil, fmt.Errorf("failed to parse response for Bunny V6 IPs from backup: %w", err)
	}

	return v6IPs, nil
}
