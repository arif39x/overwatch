package main

import (
	"crypto/md5"
	"fmt"
)

func main() {
	h := md5.New()
	h.Write([]byte("password"))
	fmt.Printf("%x", h.Sum(nil))
}
