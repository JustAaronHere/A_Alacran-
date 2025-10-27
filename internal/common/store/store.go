package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dgraph-io/badger/v4"
)

type Store struct {
	db   *badger.DB
	path string
}

type ScanResult struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Target      string                 `json:"target"`
	Status      string                 `json:"status"`
	Findings    []Finding              `json:"findings"`
	Metadata    map[string]interface{} `json:"metadata"`
	Duration    time.Duration          `json:"duration"`
}

type Finding struct {
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Target      string                 `json:"target"`
	Port        int                    `json:"port,omitempty"`
	Service     string                 `json:"service,omitempty"`
	Version     string                 `json:"version,omitempty"`
	Description string                 `json:"description"`
	CVE         []string               `json:"cve,omitempty"`
	MITRE       []string               `json:"mitre,omitempty"`
	Extra       map[string]interface{} `json:"extra,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
}

type HostInfo struct {
	IP          string                 `json:"ip"`
	Hostname    string                 `json:"hostname,omitempty"`
	OS          string                 `json:"os,omitempty"`
	OSVersion   string                 `json:"os_version,omitempty"`
	MAC         string                 `json:"mac,omitempty"`
	Ports       []PortInfo             `json:"ports"`
	LastSeen    time.Time              `json:"last_seen"`
	FirstSeen   time.Time              `json:"first_seen"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type PortInfo struct {
	Port      int                    `json:"port"`
	Protocol  string                 `json:"protocol"`
	State     string                 `json:"state"`
	Service   string                 `json:"service,omitempty"`
	Version   string                 `json:"version,omitempty"`
	Banner    string                 `json:"banner,omitempty"`
	TLS       *TLSInfo               `json:"tls,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Extra     map[string]interface{} `json:"extra,omitempty"`
}

type TLSInfo struct {
	Version     string    `json:"version"`
	CipherSuite string    `json:"cipher_suite"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	SANs        []string  `json:"sans,omitempty"`
}

func Open(path string) (*Store, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path: %w", err)
	}

	if err := os.MkdirAll(absPath, 0750); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	opts := badger.DefaultOptions(absPath).
		WithLogger(nil).
		WithLoggingLevel(badger.ERROR)

	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	return &Store{
		db:   db,
		path: absPath,
	}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) SaveScanResult(result *ScanResult) error {
	key := []byte(fmt.Sprintf("scan:%s", result.ID))
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal scan result: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(key, data)
	})
}

func (s *Store) GetScanResult(id string) (*ScanResult, error) {
	key := []byte(fmt.Sprintf("scan:%s", id))
	var result ScanResult

	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &result)
		})
	})

	if err != nil {
		return nil, err
	}

	return &result, nil
}

func (s *Store) SaveHostInfo(host *HostInfo) error {
	key := []byte(fmt.Sprintf("host:%s", host.IP))
	data, err := json.Marshal(host)
	if err != nil {
		return fmt.Errorf("failed to marshal host info: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(key, data)
	})
}

func (s *Store) GetHostInfo(ip string) (*HostInfo, error) {
	key := []byte(fmt.Sprintf("host:%s", ip))
	var host HostInfo

	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &host)
		})
	})

	if err != nil {
		return nil, err
	}

	return &host, nil
}

func (s *Store) SaveFinding(scanID string, finding *Finding) error {
	key := []byte(fmt.Sprintf("finding:%s:%d", scanID, finding.Timestamp.UnixNano()))
	data, err := json.Marshal(finding)
	if err != nil {
		return fmt.Errorf("failed to marshal finding: %w", err)
	}

	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(key, data)
	})
}

func (s *Store) ListScans(limit int) ([]*ScanResult, error) {
	var results []*ScanResult
	prefix := []byte("scan:")

	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		count := 0
		for it.Seek(prefix); it.ValidForPrefix(prefix) && count < limit; it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var result ScanResult
				if err := json.Unmarshal(val, &result); err != nil {
					return err
				}
				results = append(results, &result)
				return nil
			})
			if err != nil {
				return err
			}
			count++
		}
		return nil
	})

	return results, err
}

func (s *Store) ListHosts(limit int) ([]*HostInfo, error) {
	var hosts []*HostInfo
	prefix := []byte("host:")

	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		count := 0
		for it.Seek(prefix); it.ValidForPrefix(prefix) && count < limit; it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var host HostInfo
				if err := json.Unmarshal(val, &host); err != nil {
					return err
				}
				hosts = append(hosts, &host)
				return nil
			})
			if err != nil {
				return err
			}
			count++
		}
		return nil
	})

	return hosts, err
}

func (s *Store) DeleteOldScans(before time.Time) (int, error) {
	deleted := 0
	prefix := []byte("scan:")

	err := s.db.Update(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var result ScanResult
				if err := json.Unmarshal(val, &result); err != nil {
					return nil
				}
				if result.Timestamp.Before(before) {
					if err := txn.Delete(item.Key()); err != nil {
						return err
					}
					deleted++
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})

	return deleted, err
}

func (s *Store) RunGC() error {
	return s.db.RunValueLogGC(0.5)
}
