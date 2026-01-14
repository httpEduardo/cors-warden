package main

import (
    "bufio"
    "flag"
    "fmt"
    "os"
    "strings"
)

type Entry struct {
    Origin       string
    AllowOrigin  string
    Credentials string
}

func parseLine(line string) (Entry, error) {
    parts := strings.Split(line, "|")
    if len(parts) != 3 {
        return Entry{}, fmt.Errorf("invalid line")
    }
    return Entry{
        Origin:       strings.TrimSpace(parts[0]),
        AllowOrigin:  strings.TrimSpace(parts[1]),
        Credentials: strings.TrimSpace(parts[2]),
    }, nil
}

func analyze(entry Entry) []string {
    tags := []string{}
    if entry.AllowOrigin == "*" && strings.EqualFold(entry.Credentials, "true") {
        tags = append(tags, "wildcard-with-credentials")
    }
    if entry.AllowOrigin == entry.Origin {
        tags = append(tags, "echo-origin")
    }
    if entry.AllowOrigin != "*" && entry.AllowOrigin != entry.Origin {
        tags = append(tags, "mismatched-origin")
    }
    if strings.EqualFold(entry.Credentials, "true") {
        tags = append(tags, "credentials")
    }
    if len(tags) == 0 {
        tags = append(tags, "ok")
    }
    return tags
}

func main() {
    input := flag.String("input", "cors.txt", "Input file")
    flag.Parse()

    file, err := os.Open(*input)
    if err != nil {
        fmt.Println("Failed to open input:", err)
        os.Exit(1)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line == "" {
            continue
        }
        entry, err := parseLine(line)
        if err != nil {
            fmt.Println("Skipping invalid line:", line)
            continue
        }
        tags := analyze(entry)
        fmt.Printf("%s -> %s\n", entry.Origin, strings.Join(tags, ", "))
    }

    if err := scanner.Err(); err != nil {
        fmt.Println("Failed to read input:", err)
    }
}
