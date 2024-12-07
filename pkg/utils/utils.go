package utils

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

// WriteFile writes a file given a path and data.
func WriteFile(path string, content []byte) error {
	// open the file for writing (creates it if it doesn't exist)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("error opening file at path [%s]; %w", path, err)
	}
	defer file.Close()

	// write the []byte using a buffered writer
	writer := bufio.NewWriter(file)
	_, err = writer.Write(content)
	if err != nil {
		return fmt.Errorf("error writing content to file at path [%s]; %w", path, err)
	}

	// ensure data is flushed to the file
	writer.Flush()

	return nil
}

// ReadFile reads the file contents from a given path.
func ReadFile(path string) ([]byte, error) {
	// read the file
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error reading file; %w", err)
	}
	defer file.Close()

	// read the file contents
	contents, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("error reading file contents; %w", err)
	}

	return contents, nil
}
