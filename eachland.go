package eachland

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"text/template"

	"github.com/jessevdk/go-flags"
)

var opts struct {
	LogFormat string `long:"log-format" choice:"text" choice:"json" default:"text" description:"Log format"`
	Verbose   []bool `short:"v" long:"verbose" description:"Show verbose debug information, each -v bumps log level"`
	logLevel  slog.Level

	RootPath       string `short:"r" long:"root" description:"Root path to start scanning"`
	ActuallyDelete bool   `short:"d" long:"actually-delete" description:"Actually delete files, otherwise just report (default: false)"`
}

func Execute() int {
	if err := parseFlags(); err != nil {
		slog.Error("error parsing flags", "error", err)
		return 1
	}

	if err := setLogLevel(); err != nil {
		slog.Error("error setting log level", "error", err)
		return 1
	}

	if err := setupLogger(); err != nil {
		slog.Error("error setting up logger", "error", err)
		return 1
	}

	if err := run(); err != nil {
		slog.Error("run failed", "error", err)
		return 1
	}

	return 0
}

const reportTemplate = `
There are {{ len .Files }} files that have SHA256 checksum {{ .SHA256Sum }}.
Of those, I will keep this one:
{{ .ToKeep }}

and delete these: 
{{ range .ToDelete }}- {{ . }}
{{ end }}`

func parseFlags() error {
	_, err := flags.Parse(&opts)
	if err != nil {
		return fmt.Errorf("parse flags failed: %w", err)
	}
	return nil
}

func run() error {
	if opts.RootPath == "" {
		fmt.Println("Please provide a valid --root path.")
		os.Exit(1)
	}

	fileMap := make(map[string][]string)

	err := filepath.Walk(opts.RootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			sha256sum, err := calculateSHA256(path)
			if err != nil {
				return err
			}

			fileMap[sha256sum] = append(fileMap[sha256sum], path)
		}

		return nil
	})
	if err != nil {
		fmt.Printf("Error walking through files: %v\n", err)
		os.Exit(1)
	}

	// Report duplicate files
	for sha256sum, paths := range fileMap {
		if len(paths) > 1 {
			filesToDelete := prepareFilesToDelete(paths)
			data := ReportData{
				SHA256Sum: sha256sum,
				Files:     paths,
				ToDelete:  filesToDelete,
				ToKeep:    paths[0],
			}
			generateReport(data)

			for _, path := range filesToDelete {
				if opts.ActuallyDelete {
					slog.Info("Deleting file", "path", path)
					if err := deleteFile(path); err != nil {
						slog.Error("Error deleting file", "error", err)
					}
				}
			}
		}
	}

	return nil
}

func deleteFile(filePath string) error {
	return os.Remove(filePath)
}

func calculateSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("error calculating SHA256: %w", err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func prepareFilesToDelete(files []string) []string {
	if len(files) <= 1 {
		return nil // Nothing to delete, keep the only file
	}

	// Keep the first file and delete the rest
	return files[1:]
}

func generateReport(data ReportData) {
	tmpl, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		fmt.Printf("Error parsing template: %v\n", err)
		os.Exit(1)
	}

	err = tmpl.Execute(os.Stdout, data)
	if err != nil {
		fmt.Printf("Error executing template: %v\n", err)
		os.Exit(1)
	}
}

type ReportData struct {
	SHA256Sum string
	Files     []string
	ToDelete  []string
	ToKeep    string
}
