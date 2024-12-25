package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// ANSI escape codes for colored output
const RedText = "\033[31m"
const ResetText = "\033[0m"

// PrintHelp displays help information for the tool
func PrintHelp() {
	fmt.Println(`XSS Automation Tool - Usage:
  -urls <file>       Specify a file containing target URLs.
  -payloads <file>   Specify a file containing XSS payloads.
  -help              Display this help message.

Example:
  go run xss_tool.go -urls urls.txt -payloads payloads.txt`)
}

// ReadLines reads lines from a file and returns them as a slice of strings
func ReadLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

// TestXSS tests a URL with a given payload and checks for successful reflections
func TestXSS(targetURL string, payload string) {
	// Inject payload
	fullURL := targetURL + url.QueryEscape(payload)
	fmt.Printf("[*] Testing URL: %s\n", fullURL)

	// Send HTTP GET request
	resp, err := http.Get(fullURL)
	if err != nil {
		fmt.Printf("[-] Error: Unable to send request - %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("[-] Error reading response body: %v\n", err)
		return
	}

	// Check if the payload is reflected in the response body
	if strings.Contains(string(body), payload) {
		fmt.Printf("%s[+] Potential XSS found: %s%s\n", RedText, fullURL, ResetText)
		// Optionally, write to a file for logging
		logToFile("xss_successful.txt", fullURL)
	} else {
		fmt.Printf("[-] Payload not reflected: %s\n", fullURL)
	}
}

// logToFile logs the successful URLs to a file
func logToFile(filename string, data string) {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("[-] Error writing to file: %v\n", err)
		return
	}
	defer file.Close()

	if _, err := file.WriteString(data + "\n"); err != nil {
		fmt.Printf("[-] Error writing to file: %v\n", err)
	}
}

func main() {
	// Define command-line flags
	urlsFile := flag.String("urls", "", "File containing target URLs")
	payloadsFile := flag.String("payloads", "", "File containing XSS payloads")
	helpFlag := flag.Bool("help", false, "Display help message")

	flag.Parse()

	// Display help if requested or if no arguments provided
	if *helpFlag || *urlsFile == "" || *payloadsFile == "" {
		PrintHelp()
		return
	}

	// Read URLs from file
	urls, err := ReadLines(*urlsFile)
	if err != nil {
		fmt.Printf("[-] Error reading URLs file: %v\n", err)
		return
	}

	// Read payloads from file
	payloads, err := ReadLines(*payloadsFile)
	if err != nil {
		fmt.Printf("[-] Error reading payloads file: %v\n", err)
		return
	}

	// Test each URL with each payload
	for _, url := range urls {
		for _, payload := range payloads {
			TestXSS(strings.TrimSpace(url), strings.TrimSpace(payload))
		}
	}
}
