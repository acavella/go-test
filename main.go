package main

import (
	"crypto/x509"
	"fmt"

	"os"
)

func main() {

	csr, err := os.ReadFile("x21.crl")
	if err != nil {
		fmt.Print(err)
	} else {
		_, err := x509.ParseRevocationList(csr)
		if err == nil {
			return
		} else {
			fmt.Print(err)
		}
	}

}
