package main

import (
	"crypto/x509"
	"fmt"
	"log"
	"os"
)

func main() {

	csr, err := os.ReadFile("x21.crl")
	if err != nil {
		log.Fatal(err)
	}

	cert, err := x509.ParseRevocationList(csr)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Name %s\n", cert.Issuer.CommonName)
	fmt.Printf("Not before %s\n", cert.ThisUpdate.String())
	fmt.Printf("Not after %s\n", cert.NextUpdate.String())

}
