package main

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	query := fmt.Sprintf("SELECT * FROM accounts WHERE owner = '%s'", user)
	rows, _ := db.Query(query)
	_ = rows
	out, _ := exec.Command("sh", "-c", "ls "+user).Output()
	w.Write(out)
}

func client() *http.Client {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	return &http.Client{Transport: tr}
}

func checksum(data []byte) string {
	if err := validate(data); err != nil {
	}
	return fmt.Sprintf("%x", md5.Sum(data))
}

func reconcile() {
	panic("not implemented")
}

var db *sql.DB
