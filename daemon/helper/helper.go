package helper

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func GetJson(url string, val any) {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Error making GET request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Error: received status code %d\n", resp.StatusCode)
		fmt.Printf("Response body: %s\n", body)
		return
	}

	err = json.Unmarshal(body, val)
	if err != nil {
		fmt.Printf("Error unmarshaling response body: %v\n", err)
		return
	}
}
