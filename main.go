package main

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type options struct {
	jsonOut         string
	markdownOut     string
	includeTCPStats bool
}

type connection struct {
	Protocol   string `json:"protocol"`
	LocalAddr  string `json:"local_addr"`
	LocalPort  int    `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort int    `json:"remote_port"`
	State      string `json:"state"`
	PID        int    `json:"pid"`
}

type processInfo struct {
	PID      int      `json:"pid"`
	Image    string   `json:"image"`
	Services []string `json:"services,omitempty"`
}

type listenerFinding struct {
	Connection     connection  `json:"connection"`
	Process        processInfo `json:"process"`
	Exposure       string      `json:"exposure"`
	RiskScore      int         `json:"risk_score"`
	RiskLabel      string      `json:"risk_label"`
	Recommendation string      `json:"recommendation"`
}

type report struct {
	GeneratedAt       string            `json:"generated_at"`
	Host              string            `json:"host"`
	ListenerCount     int               `json:"listener_count"`
	ExposureBreakdown map[string]int    `json:"exposure_breakdown"`
	Findings          []listenerFinding `json:"findings"`
	TCPStats          map[string]string `json:"tcp_stats,omitempty"`
}

func parseFlags() options {
	var opts options
	flag.StringVar(&opts.jsonOut, "json-out", "", "Optional JSON report path.")
	flag.StringVar(&opts.markdownOut, "markdown-out", "", "Optional Markdown report path.")
	flag.BoolVar(&opts.includeTCPStats, "include-tcp-stats", false, "Include netstat -s TCP counters in the report.")
	flag.Parse()
	return opts
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	opts := parseFlags()
	processes, err := loadProcessMap()
	if err != nil {
		return err
	}

	connections, err := loadTCPConnections()
	if err != nil {
		return err
	}

	findings := buildFindings(connections, processes)
	tcpStats := map[string]string{}
	if opts.includeTCPStats {
		tcpStats, err = loadTCPStats()
		if err != nil {
			return err
		}
	}

	host, _ := os.Hostname()
	rep := report{
		GeneratedAt:       nowISO(),
		Host:              host,
		ListenerCount:     len(findings),
		ExposureBreakdown: buildExposureBreakdown(findings),
		Findings:          findings,
		TCPStats:          tcpStats,
	}

	printConsoleSummary(rep)
	if opts.jsonOut != "" {
		if err := writeJSON(opts.jsonOut, rep); err != nil {
			return err
		}
		fmt.Printf("Wrote JSON report: %s\n", opts.jsonOut)
	}
	if opts.markdownOut != "" {
		if err := writeMarkdown(opts.markdownOut, rep); err != nil {
			return err
		}
		fmt.Printf("Wrote Markdown report: %s\n", opts.markdownOut)
	}
	return nil
}

func nowISO() string {
	return time.Now().Format(time.RFC3339)
}

func loadProcessMap() (map[int]processInfo, error) {
	tasklist, err := runCommand("tasklist", "/svc", "/fo", "csv", "/nh")
	if err != nil {
		return nil, err
	}

	reader := csv.NewReader(strings.NewReader(tasklist))
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	processes := map[int]processInfo{}
	for _, record := range records {
		if len(record) < 3 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(record[1]))
		if err != nil {
			continue
		}
		services := []string{}
		for _, raw := range strings.Split(record[2], ",") {
			service := strings.TrimSpace(raw)
			if service != "" && !strings.EqualFold(service, "N/A") {
				services = append(services, service)
			}
		}
		processes[pid] = processInfo{
			PID:      pid,
			Image:    strings.TrimSpace(record[0]),
			Services: services,
		}
	}
	return processes, nil
}

func loadTCPConnections() ([]connection, error) {
	output, err := runCommand("netstat", "-ano", "-p", "tcp")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(output, "\n")
	var connections []connection
	for _, line := range lines {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 5 || !strings.EqualFold(fields[0], "TCP") {
			continue
		}

		localAddr, localPort, err := splitEndpoint(fields[1])
		if err != nil {
			continue
		}
		remoteAddr, remotePort, err := splitEndpoint(fields[2])
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(fields[4])
		if err != nil {
			continue
		}
		if !strings.EqualFold(fields[3], "LISTENING") {
			continue
		}

		connections = append(connections, connection{
			Protocol:   "tcp",
			LocalAddr:  localAddr,
			LocalPort:  localPort,
			RemoteAddr: remoteAddr,
			RemotePort: remotePort,
			State:      fields[3],
			PID:        pid,
		})
	}

	sort.Slice(connections, func(i, j int) bool {
		if connections[i].LocalPort != connections[j].LocalPort {
			return connections[i].LocalPort < connections[j].LocalPort
		}
		return connections[i].PID < connections[j].PID
	})
	return connections, nil
}

func loadTCPStats() (map[string]string, error) {
	output, err := runCommand("netstat", "-s", "-p", "tcp")
	if err != nil {
		return nil, err
	}

	stats := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		clean := strings.TrimSpace(line)
		if clean == "" || !strings.Contains(clean, "=") {
			continue
		}
		parts := strings.SplitN(clean, "=", 2)
		stats[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return stats, nil
}

func buildFindings(connections []connection, processes map[int]processInfo) []listenerFinding {
	findings := make([]listenerFinding, 0, len(connections))
	for _, conn := range connections {
		process := processes[conn.PID]
		if process.PID == 0 {
			process = processInfo{PID: conn.PID, Image: "unknown"}
		}
		exposure := classifyExposure(conn.LocalAddr)
		score, label, recommendation := scoreListener(conn, process, exposure)
		findings = append(findings, listenerFinding{
			Connection:     conn,
			Process:        process,
			Exposure:       exposure,
			RiskScore:      score,
			RiskLabel:      label,
			Recommendation: recommendation,
		})
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].RiskScore != findings[j].RiskScore {
			return findings[i].RiskScore > findings[j].RiskScore
		}
		if findings[i].Connection.LocalPort != findings[j].Connection.LocalPort {
			return findings[i].Connection.LocalPort < findings[j].Connection.LocalPort
		}
		return findings[i].Process.Image < findings[j].Process.Image
	})
	return findings
}

func buildExposureBreakdown(findings []listenerFinding) map[string]int {
	breakdown := map[string]int{}
	for _, finding := range findings {
		breakdown[finding.Exposure]++
	}
	return breakdown
}

func classifyExposure(address string) string {
	normalized := strings.Trim(address, "[]")
	switch normalized {
	case "0.0.0.0", "::", "*":
		return "wildcard"
	case "127.0.0.1", "::1", "localhost":
		return "loopback"
	}

	ip := net.ParseIP(normalized)
	if ip == nil {
		return "named"
	}
	if ip.IsLoopback() {
		return "loopback"
	}
	if ip.IsPrivate() {
		return "private-lan"
	}
	return "specific-interface"
}

func scoreListener(conn connection, process processInfo, exposure string) (int, string, string) {
	score := 10
	recommendation := "Leave as-is if this service is expected."

	switch exposure {
	case "wildcard":
		score = 78
		recommendation = "Verify this service should accept traffic from every interface."
	case "private-lan":
		score = 58
		recommendation = "Confirm LAN exposure is intentional and firewall rules are tight."
	case "specific-interface", "named":
		score = 42
		recommendation = "Confirm the bound interface matches the intended audience."
	case "loopback":
		score = 16
		recommendation = "Low exposure. Keep it loopback-only if remote access is unnecessary."
	}

	switch conn.LocalPort {
	case 22, 80, 443, 3000, 5000, 5432, 6379, 8000, 8080, 27017, 3306, 3389:
		score += 8
	case 135, 445:
		score += 4
	}

	image := strings.ToLower(process.Image)
	if strings.Contains(image, "python") || strings.Contains(image, "node") || strings.Contains(image, "java") || strings.Contains(image, "php") {
		score += 5
		recommendation = "Developer runtime detected. Check whether this listener should stay local-only."
	}

	if len(process.Services) > 0 {
		score -= 8
	}

	if score < 20 {
		return score, "low", recommendation
	}
	if score < 55 {
		return score, "moderate", recommendation
	}
	if score < 75 {
		return score, "elevated", recommendation
	}
	return score, "high", recommendation
}

func writeJSON(path string, rep report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func writeMarkdown(path string, rep report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	lines := []string{
		"# Listener Surface Audit",
		"",
		fmt.Sprintf("- Host: `%s`", rep.Host),
		fmt.Sprintf("- Generated: `%s`", rep.GeneratedAt),
		fmt.Sprintf("- Listening TCP sockets: `%d`", rep.ListenerCount),
		"",
		"## Exposure breakdown",
	}
	keys := make([]string, 0, len(rep.ExposureBreakdown))
	for key := range rep.ExposureBreakdown {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		lines = append(lines, fmt.Sprintf("- `%s`: `%d`", key, rep.ExposureBreakdown[key]))
	}

	lines = append(lines, "", "## Highest-risk listeners")
	for index, finding := range rep.Findings {
		if index >= 12 {
			break
		}
		lines = append(lines,
			fmt.Sprintf("### %s on %s:%d", finding.Process.Image, finding.Connection.LocalAddr, finding.Connection.LocalPort),
			fmt.Sprintf("- PID: `%d`", finding.Process.PID),
			fmt.Sprintf("- Exposure: `%s`", finding.Exposure),
			fmt.Sprintf("- Risk: `%s` (%d/100)", finding.RiskLabel, finding.RiskScore),
			fmt.Sprintf("- Recommendation: %s", finding.Recommendation),
		)
		if len(finding.Process.Services) > 0 {
			lines = append(lines, fmt.Sprintf("- Services: `%s`", strings.Join(finding.Process.Services, ", ")))
		}
		lines = append(lines, "")
	}

	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644)
}

func printConsoleSummary(rep report) {
	fmt.Println("Listener Surface Auditor")
	fmt.Println("========================")
	fmt.Printf("Host:                 %s\n", rep.Host)
	fmt.Printf("Listening TCP ports:  %d\n", rep.ListenerCount)
	fmt.Println("Exposure breakdown:")
	keys := make([]string, 0, len(rep.ExposureBreakdown))
	for key := range rep.ExposureBreakdown {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Printf("  %-18s %d\n", key, rep.ExposureBreakdown[key])
	}
	fmt.Println()
	fmt.Println("Top listeners:")
	for index, finding := range rep.Findings {
		if index >= 8 {
			break
		}
		fmt.Printf("  %-20s %-15s:%-5d %-9s %3d/100 %s\n",
			finding.Process.Image,
			finding.Connection.LocalAddr,
			finding.Connection.LocalPort,
			finding.Exposure,
			finding.RiskScore,
			finding.Recommendation,
		)
	}
}

func splitEndpoint(value string) (string, int, error) {
	if strings.HasPrefix(value, "[") {
		parts := strings.Split(value, "]:")
		if len(parts) != 2 {
			return "", 0, errors.New("invalid endpoint")
		}
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			return "", 0, err
		}
		return strings.TrimPrefix(parts[0], "["), port, nil
	}

	index := strings.LastIndex(value, ":")
	if index == -1 {
		return "", 0, errors.New("invalid endpoint")
	}
	port, err := strconv.Atoi(value[index+1:])
	if err != nil {
		return "", 0, err
	}
	return value[:index], port, nil
}

func runCommand(name string, args ...string) (string, error) {
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s %v failed: %w\n%s", name, args, err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}
