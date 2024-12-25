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
  go run xss_tool.go -urls urls.txt -payloads payloads.txt
`)
}

// ReadLines reads lines from a file and returns them as a slice of strings
func ReadLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("unable to open file %s: %v", filename, err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file %s: %v", filename, err)
	}
	return lines, nil
}

// TestXSS tests a URL with a given payload
func TestXSS(targetURL string, payload string) {
	// Construct the full URL with the payload
	fullURL := targetURL + url.QueryEscape(payload)
	fmt.Printf("[*] Testing URL: %s\n", fullURL)

	// Send HTTP GET request
	resp, err := http.Get(fullURL)
	if err != nil {
		fmt.Printf("[-] Error: Unable to send request to %s - %v\n", fullURL, err)
		return
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("[-] Received non-OK response: %d\n", resp.StatusCode)
		return
	}

	// Read response body
	body := make([]byte, resp.ContentLength)
	_, err = resp.Body.Read(body)
	if err != nil && err.Error() != "EOF" {
		fmt.Printf("[-] Error reading response body for %s: %v\n", fullURL, err)
		return
	}
	bodyStr := string(body)

	// Look for the payload in the response body using a regex match
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
		fmt.Println(err)
		return
	}

	// Read payloads from file
	payloads, err := ReadLines(*payloadsFile)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Test each URL with each payload
	for _, url := range urls {
		for _, payload := range payloads {
			// Trim spaces and test the URL with the payload
			TestXSS(strings.TrimSpace(url), strings.TrimSpace(payload))
		}
	}
}
