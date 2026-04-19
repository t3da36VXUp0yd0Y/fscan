package main

import (
	"fmt"
	"os"

	"github.com/shadow1ng/fscan/Core"
	"github.com/shadow1ng/fscan/common"
)

func main() {
	// Parse command-line arguments and initialize scan configuration
	var info common.HostInfo
	common.Flag(&info)
	common.Parse(&info)

	// Run the core scanning engine
	err := Core.Scan(info)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Scan failed: %v\n", err)
		os.Exit(1)
	}

	// Print a completion message so it's clear the scan finished successfully
	fmt.Println("[INFO] Scan completed.")
}
