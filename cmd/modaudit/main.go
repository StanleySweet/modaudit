package main

import (
	"fmt"
	"os"
)

const usage = `usage: modaudit <command> [flags]

commands:
  audit   audit a mod zip and write a report
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 1
	}
	switch args[0] {
	case "audit":
		fmt.Fprintln(os.Stderr, "audit: not implemented")
		return 1
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", args[0], usage)
		return 1
	}
}
