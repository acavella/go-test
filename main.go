package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"fmt"
	"log"
	"math/big"
	"time"

	"os"

	_ "github.com/mattn/go-sqlite3"
)

const crlfile string = "x21.crl"
const dbfile string = "revoke.db"

type RevocationListEntry struct {
	Raw             []byte
	SerialNumber    *big.Int
	RevocationTime  time.Time
	ReasonCode      int
	Extensions      []pkix.Extension
	ExtraExtensions []pkix.Extension
}

func main() {
	parsecrl(crlfile)
	sqliteDatabase, _ := sql.Open("sqlite3", dbfile) //https://www.codeproject.com/Articles/5261771/Golang-SQLite-Simple-Example
	defer sqliteDatabase.Close()
	insertCertificate(sqliteDatabase, 0, "text", 0)

}

func insertCertificate(db *sql.DB, serial int, revocationtime string, reasoncode int) {
	insertCertificateSQL := `INSERT INTO table-name(revocationtime,serial,reasoncode) VALUES (NULL,NULL,NULL,?,?,?)`
	statement, err := db.Prepare(insertCertificateSQL)
	if err != nil {
		log.Fatalln(err.Error())
	}
	_, err = statement.Exec(revocationtime, serial, reasoncode)
	if err != nil {
		log.Fatalln(err.Error())
	}
}

func parsecrl(file string) {
	crl, err := os.ReadFile(file)
	if err != nil {
		fmt.Print(err)
	} else {
		cert, err := x509.ParseRevocationList(crl)
		if err == nil {
			fmt.Println("CRL Issuer: ", cert.Issuer.CommonName)
			fmt.Println("Issued: ", cert.ThisUpdate)
			fmt.Println("Next Update: ", cert.NextUpdate)
			//fmt.Println(cert.RevokedCertificateEntries)
			for i := 0; i < len(cert.RevokedCertificateEntries); i++ {
				fmt.Println("SerialNum: ", cert.RevokedCertificateEntries[i].SerialNumber)
				fmt.Println("RevocationTime: ", cert.RevokedCertificateEntries[i].RevocationTime)
			}
		} else {
			fmt.Print(err)
		}
	}
}
