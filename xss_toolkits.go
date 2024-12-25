package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"regexp"
)

// Color definitions for terminal output
const (
	RED    = "\033[0;31m"
	GREEN  = "\033[0;32m"
	NC     = "\033[0m" // No color
)

// PrintHelp displays help information for the tool
func PrintHelp() {
	fmt.Println(`XSS Automation Tool
Created by Moazam Hameed

Usage:
  -urls <file>       Specify a file containing target URLs.
  -payloads <file>   Specify a file containing XSS payloads.
  -help              Display this help message.

Example:
  xss_toolkit -urls urls.txt -payloads payloads.txt
`)
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

// TestXSS tests a URL with a given payload
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

	// Check if the payload is reflected in the response body
	body := make([]byte, resp.ContentLength)
	resp.Body.Read(body)
	bodyStr := string(body)

	// Look for the payload in the response body using a simple regex match
	re := regexp.MustCompile(regexp.QuoteMeta(payload))
	if re.MatchString(bodyStr) {
		fmt.Printf("%s[REFLECTED XSS FOUND]%s Potential XSS vulnerability in parameter: %s\n", RED, NC, payload)
	} else {
		fmt.Printf("%s[SAFE]%s No XSS found for parameter: %s\n", GREEN, NC, payload)
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
