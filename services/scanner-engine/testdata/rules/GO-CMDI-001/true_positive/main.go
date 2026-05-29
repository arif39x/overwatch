package main

import (
	"os"
	"os/exec"
)

func main() {
	cmd := os.Getenv("CMD")
	exec.Command(cmd)
}
