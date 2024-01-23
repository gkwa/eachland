package main

import (
	"os"

	"github.com/taylormonacelli/eachland"
)

func main() {
	code := eachland.Execute()
	os.Exit(code)
}
