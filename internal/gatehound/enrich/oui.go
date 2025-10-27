package enrich

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
)

type OUIDatabase struct {
	mu      sync.RWMutex
	ouiMap  map[string]string
	dbPath  string
}

type OUIInfo struct {
	Prefix      string
	Vendor      string
	VendorShort string
}

func NewOUIDatabase(dbPath string) (*OUIDatabase, error) {
	db := &OUIDatabase{
		ouiMap: make(map[string]string),
		dbPath: dbPath,
	}

	if dbPath != "" {
		if err := db.Load(); err != nil {
			return db, err
		}
	} else {
		db.loadBuiltinOUI()
	}

	return db, nil
}

func (db *OUIDatabase) Load() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	file, err := os.Open(db.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open OUI database: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.Comment = '#'

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		if len(record) >= 2 {
			prefix := strings.ToUpper(strings.TrimSpace(record[0]))
			vendor := strings.TrimSpace(record[1])
			db.ouiMap[prefix] = vendor
		}
	}

	return nil
}

func (db *OUIDatabase) loadBuiltinOUI() {
	builtinOUI := map[string]string{
		"00:00:00": "XEROX CORPORATION",
		"00:00:01": "XEROX CORPORATION",
		"00:00:0C": "Cisco Systems, Inc",
		"00:00:0E": "FUJITSU LIMITED",
		"00:01:42": "Cisco Systems, Inc",
		"00:01:43": "Cisco Systems, Inc",
		"00:03:47": "Intel Corporation",
		"00:04:5A": "Linksys",
		"00:05:69": "VMware, Inc.",
		"00:0A:27": "Apple, Inc.",
		"00:0C:29": "VMware, Inc.",
		"00:0D:3A": "Microsoft Corporation",
		"00:11:22": "CIMSYS Inc",
		"00:13:72": "Dell Inc.",
		"00:15:5D": "Microsoft Corporation",
		"00:16:3E": "Xensource, Inc.",
		"00:17:42": "Parallels, Inc.",
		"00:1B:21": "Intel Corporation",
		"00:1C:14": "Cisco Systems, Inc",
		"00:1C:42": "Parallels, Inc.",
		"00:50:56": "VMware, Inc.",
		"08:00:27": "PCS Systemtechnik GmbH",
		"18:03:73": "Raspberry Pi Foundation",
		"28:CD:C1": "Apple, Inc.",
		"3C:07:54": "Apple, Inc.",
		"50:ED:3C": "Google, Inc.",
		"52:54:00": "QEMU",
		"54:52:00": "Oracle Corporation",
		"B8:27:EB": "Raspberry Pi Foundation",
		"DC:A6:32": "Raspberry Pi Foundation",
		"E4:5F:01": "Raspberry Pi Foundation",
		"FC:AA:14": "Apple, Inc.",
	}

	db.mu.Lock()
	defer db.mu.Unlock()
	for prefix, vendor := range builtinOUI {
		db.ouiMap[prefix] = vendor
	}
}

func (db *OUIDatabase) Lookup(mac net.HardwareAddr) *OUIInfo {
	if len(mac) < 3 {
		return nil
	}

	prefix := fmt.Sprintf("%02X:%02X:%02X", mac[0], mac[1], mac[2])

	db.mu.RLock()
	vendor, exists := db.ouiMap[prefix]
	db.mu.RUnlock()

	if !exists {
		return &OUIInfo{
			Prefix:      prefix,
			Vendor:      "Unknown",
			VendorShort: "Unknown",
		}
	}

	return &OUIInfo{
		Prefix:      prefix,
		Vendor:      vendor,
		VendorShort: shortenVendorName(vendor),
	}
}

func (db *OUIDatabase) LookupString(macStr string) *OUIInfo {
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		return nil
	}
	return db.Lookup(mac)
}

func shortenVendorName(vendor string) string {
	vendor = strings.ReplaceAll(vendor, ", Inc.", "")
	vendor = strings.ReplaceAll(vendor, " Inc.", "")
	vendor = strings.ReplaceAll(vendor, ", LLC", "")
	vendor = strings.ReplaceAll(vendor, " LLC", "")
	vendor = strings.ReplaceAll(vendor, " Corporation", "")
	vendor = strings.ReplaceAll(vendor, " Corp.", "")
	vendor = strings.ReplaceAll(vendor, " Limited", "")
	vendor = strings.ReplaceAll(vendor, " Ltd.", "")
	vendor = strings.ReplaceAll(vendor, "CORPORATION", "")

	if len(vendor) > 30 {
		vendor = vendor[:27] + "..."
	}

	return strings.TrimSpace(vendor)
}

func (db *OUIDatabase) UpdateFromFile(path string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ",", 2)
		if len(parts) == 2 {
			prefix := strings.ToUpper(strings.TrimSpace(parts[0]))
			vendor := strings.TrimSpace(parts[1])
			db.ouiMap[prefix] = vendor
		}
	}

	return scanner.Err()
}

func (db *OUIDatabase) Count() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.ouiMap)
}
