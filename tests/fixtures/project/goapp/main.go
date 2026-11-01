package main

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"

	"golang.org/x/text/language"
)

func token() int {
	return rand.Int()
}

func run(name string) error {
	cmd := exec.Command("sh", "-c", name)
	return cmd.Run()
}

func client() *http.Client {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	return &http.Client{Transport: tr}
}

func main() {
	tags, _, _ := language.ParseAcceptLanguage(os.Getenv("LANG_HDR"))
	fmt.Println(tags, token())
	_ = run(os.Args[1])
	_ = client()
}
