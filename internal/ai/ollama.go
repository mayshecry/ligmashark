package ai

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"ligmashark/internal/types"
)

type OllamaResponse struct {
	Response string `json:"response"`
}

type OllamaTagsResponse struct {
	Models []struct {
		Name string `json:"name"`
	} `json:"models"`
}

const ollamaAPIURL = "http://localhost:11434"

func CheckOllamaServer() bool {
	client := http.Client{Timeout: 1 * time.Second}
	resp, err := client.Get(ollamaAPIURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func StartOllamaServer() error {
	cmd := exec.Command("ollama", "serve")
	cmd.SysProcAttr = nil
	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("failed to start ollama: %w", err)
	}
	return nil
}

func CheckModelInstalled(modelName string) (bool, error) {
	resp, err := http.Get(ollamaAPIURL + "/api/tags")
	if err != nil {
		return false, fmt.Errorf("failed to query ollama models: %w", err)
	}
	defer resp.Body.Close()

	var tags OllamaTagsResponse
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return false, fmt.Errorf("failed to decode ollama tags response: %w", err)
	}

	for _, model := range tags.Models {
		if model.Name == modelName {
			return true, nil
		}
	}
	return false, nil
}

func AnalyzePayload(pkt types.PacketData) (string, error) {
	url := "http://localhost:11434/api/generate"

	procName := strings.ToLower(pkt.ProcessName)
	hint := ""
	if strings.Contains(procName, "discord") && pkt.Protocol == "UDP" {
		hint = "Note: This traffic pattern is characteristic of a Discord voice/video call session.\n"
	}

	prompt := fmt.Sprintf("Analyze this network packet as a technical expert. %s"+
		"Explain what this packet is doing and its probable intent. Be objective and technical; do not assume malicious intent or 'hacking' unless explicitly clear. "+
		"IMPORTANT: Do not use any markdown formatting. Do not use bold text (no ** characters). Provide only plain text in a single paragraph.\n\n"+
		"Protocol: %s\n" +
		"Source: %s:%s\n" +
		"Destination: %s:%s\n" +
		"ISP: %s\n" +
		"Process: %s\n" +
		"Detected Service: %s\n" +
		"Payload Hex Dump:\n%s",
		hint, pkt.Protocol, pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, pkt.ISP, pkt.ProcessName, pkt.Service, pkt.Payload)

	body, err := json.Marshal(map[string]interface{}{
		"model":  "qwen2.5:0.5b",
		"prompt": prompt,
		"stream": false,
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON for Ollama request: %w", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errBody map[string]string
		json.NewDecoder(resp.Body).Decode(&errBody)
		return "", errors.New(errBody["error"])
	}

	var res OllamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", err
	}
	return res.Response, nil
}