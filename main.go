package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	// use our own go-ldap so we can ensure we dont include CBT
	"github.com/DriftSec/ldapcheck/ldap"
)

const (
	colorReset = "\033[0m"
	colorRed   = "\033[31m"
	colorGreen = "\033[32m"
)

var (
	targetArg string
	targets   []string
	dom_user  string
	user      string
	pass      string
	hash      string
	domain    string
	relayFile string
	relayLst  []string
)

func main() {
	flag.StringVar(&targetArg, "t", "", "target address or file containing targets")
	flag.StringVar(&dom_user, "u", "", "username, formats: user@domain or domain\\user")
	flag.StringVar(&pass, "p", "", "user password")
	flag.StringVar(&hash, "H", "", "user NTLM hash")
	flag.StringVar(&relayFile, "relay-list", "", "generate a relay list for use with ntlmrelayx.py")
	flag.Parse()

	if targetArg == "" {
		log.Fatal("[ERROR] target IP (-t) is required!")
	}

	if _, err := os.Stat(targetArg); errors.Is(err, os.ErrNotExist) {
		targets = append(targets, targetArg)
	} else {
		targets, err = readLines(targetArg)
		if err != nil {
			log.Fatal(err)
		}
	}

	if dom_user == "" {
		fmt.Println("[!] No username provided, signing check will be skipped\n")
	} else {
		if strings.Contains(dom_user, "@") {
			tmp := strings.Split(dom_user, "@")
			user = tmp[0]
			domain = tmp[1]
		} else if strings.Contains(dom_user, "/") {
			tmp := strings.Split(dom_user, "/")
			user = tmp[1]
			domain = tmp[0]
		} else if strings.Contains(dom_user, "\\") {
			tmp := strings.Split(dom_user, "\\")
			user = tmp[1]
			domain = tmp[0]
		} else {
			log.Fatal("[ERROR] Username must include the domain!")
		}

		if pass == "" && hash == "" {
			log.Fatal("[ERROR] Must specify -p or -H to authenticate")
		}
	}

	for _, target := range targets {

		fmt.Println("[!] Checking " + target)
		// Check LDAP for signing, if we have creds
		if dom_user != "" {
			ldapURL := "ldap://" + target + ":389"

			l, err := ldap.DialURL(ldapURL)
			if err != nil {
				log.Fatal(err)
			}
			defer l.Close()

			// err = l.Bind(user+"@"+domain, pass)
			if pass != "" {
				err = l.NTLMBind(domain, user, pass)
			} else if hash != "" {
				err = l.NTLMBindWithHash(domain, user, hash)
			} else {
				log.Fatal("[ERROR] Must specify -p or -H to authenticate")
			}

			if err != nil && strings.Contains(err.Error(), "Strong Auth Required") {
				fmt.Println(colorRed + "	signing is enforced on ldap://" + target + colorReset)
			} else if err != nil && strings.Contains(err.Error(), "Invalid Credentials") {
				fmt.Println("LDAP: Auth Failed,  valid creds are required to check signing!")
			} else {
				fmt.Println(colorGreen + "	signing is NOT enforced, we can relay to ldap://" + target + colorReset)
				relayLst = append(relayLst, "ldap://"+target)

			}
		}

		// Check LDAPS for channel binding
		ldapsURL := "ldaps://" + target + ":636"

		ls, err := ldap.DialURL(ldapsURL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
		if err != nil {
			log.Fatal(err)
		}
		defer ls.Close()
		err = ls.NTLMBind("blah", "blah", "blah")
		if err != nil && strings.Contains(err.Error(), "data 80090346") {
			fmt.Println(colorRed + "	channel binding is enforced on ldaps://" + target + colorReset)
		} else {
			fmt.Println(colorGreen + "	channel binding is NOT enforced, we can relay to ldaps://" + target + colorReset)
			relayLst = append(relayLst, "ldaps://"+target)
		}
	}
	if len(relayLst) > 0 && relayFile != "" {
		err := writeLines(relayLst, relayFile)
		if err != nil {
			log.Fatal(err)
		}
	}
}

// readLines reads a whole file into memory
// and returns a slice of its lines.
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// writeLines writes the lines to the given file.
func writeLines(lines []string, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}
