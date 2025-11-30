package filescanner

import (
	"bufio"
	"log"
	"os"
)

func FileScan(path string) {
	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		log.Println(line)
	}
}
