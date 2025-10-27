package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aegis-sentinel/aegis-suite/internal/common/store"
	"github.com/aegis-sentinel/aegis-suite/internal/gatehound/monitor"
)

type EvidenceType string

const (
	EvidenceTypePcap       EvidenceType = "pcap"
	EvidenceTypeEvent      EvidenceType = "event"
	EvidenceTypeDevice     EvidenceType = "device"
	EvidenceTypeIncident   EvidenceType = "incident"
	EvidenceTypeReport     EvidenceType = "report"
)

type Evidence struct {
	ID               string                 `json:"id"`
	Type             EvidenceType           `json:"type"`
	Timestamp        time.Time              `json:"timestamp"`
	CollectedBy      string                 `json:"collected_by"`
	Description      string                 `json:"description"`
	FilePath         string                 `json:"file_path,omitempty"`
	FileHash         string                 `json:"file_hash,omitempty"`
	FileSize         int64                  `json:"file_size,omitempty"`
	Encrypted        bool                   `json:"encrypted"`
	EncryptionMethod string                 `json:"encryption_method,omitempty"`
	Signature        string                 `json:"signature,omitempty"`
	SignatureMethod  string                 `json:"signature_method,omitempty"`
	ChainOfCustody   []CustodyEntry         `json:"chain_of_custody"`
	RelatedIncidents []string               `json:"related_incidents,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

type CustodyEntry struct {
	Timestamp   time.Time              `json:"timestamp"`
	Operator    string                 `json:"operator"`
	Action      string                 `json:"action"`
	Description string                 `json:"description,omitempty"`
	Location    string                 `json:"location,omitempty"`
	Signature   string                 `json:"signature,omitempty"`
	Extra       map[string]interface{} `json:"extra,omitempty"`
}

type Manifest struct {
	ID            string                 `json:"id"`
	CreatedAt     time.Time              `json:"created_at"`
	Version       string                 `json:"version"`
	Evidence      []*Evidence            `json:"evidence"`
	TotalFiles    int                    `json:"total_files"`
	TotalSize     int64                  `json:"total_size"`
	ManifestHash  string                 `json:"manifest_hash"`
	Signature     string                 `json:"signature"`
	SignedBy      string                 `json:"signed_by"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

type EvidenceStore struct {
	store      *store.Store
	basePath   string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	operator   string
}

func NewEvidenceStore(st *store.Store, basePath string, operator string) (*EvidenceStore, error) {
	if err := os.MkdirAll(basePath, 0750); err != nil {
		return nil, fmt.Errorf("failed to create evidence directory: %w", err)
	}

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signing keys: %w", err)
	}

	return &EvidenceStore{
		store:      st,
		basePath:   basePath,
		privateKey: privKey,
		publicKey:  pubKey,
		operator:   operator,
	}, nil
}

func (es *EvidenceStore) StoreEvent(event *monitor.NetworkEvent, description string) (*Evidence, error) {
	eventData, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal event: %w", err)
	}

	hash := sha256.Sum256(eventData)
	hashStr := hex.EncodeToString(hash[:])

	evidence := &Evidence{
		ID:          fmt.Sprintf("evt-%s", event.ID),
		Type:        EvidenceTypeEvent,
		Timestamp:   event.Timestamp,
		CollectedBy: es.operator,
		Description: description,
		FileHash:    hashStr,
		Encrypted:   false,
		Metadata: map[string]interface{}{
			"event_type": event.Type,
			"src_ip":     event.SrcIP,
			"dst_ip":     event.DstIP,
		},
		ChainOfCustody: []CustodyEntry{
			{
				Timestamp:   time.Now(),
				Operator:    es.operator,
				Action:      "collected",
				Description: "Event captured and stored",
			},
		},
	}

	signature := ed25519.Sign(es.privateKey, eventData)
	evidence.Signature = hex.EncodeToString(signature)
	evidence.SignatureMethod = "ed25519"

	if err := es.persistEvidence(evidence, eventData); err != nil {
		return nil, err
	}

	return evidence, nil
}

func (es *EvidenceStore) StoreDevice(device *monitor.DeviceInfo, description string) (*Evidence, error) {
	deviceData, err := json.Marshal(device)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal device: %w", err)
	}

	hash := sha256.Sum256(deviceData)
	hashStr := hex.EncodeToString(hash[:])

	evidence := &Evidence{
		ID:          fmt.Sprintf("dev-%s", device.MAC.String()),
		Type:        EvidenceTypeDevice,
		Timestamp:   time.Now(),
		CollectedBy: es.operator,
		Description: description,
		FileHash:    hashStr,
		Encrypted:   false,
		Metadata: map[string]interface{}{
			"mac":       device.MAC.String(),
			"vendor":    device.Vendor,
			"is_known":  device.IsKnown,
		},
		ChainOfCustody: []CustodyEntry{
			{
				Timestamp:   time.Now(),
				Operator:    es.operator,
				Action:      "collected",
				Description: "Device information captured",
			},
		},
	}

	signature := ed25519.Sign(es.privateKey, deviceData)
	evidence.Signature = hex.EncodeToString(signature)
	evidence.SignatureMethod = "ed25519"

	if err := es.persistEvidence(evidence, deviceData); err != nil {
		return nil, err
	}

	return evidence, nil
}

func (es *EvidenceStore) StorePcap(pcapPath string, description string) (*Evidence, error) {
	fileInfo, err := os.Stat(pcapPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat pcap file: %w", err)
	}

	fileData, err := os.ReadFile(pcapPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read pcap file: %w", err)
	}

	hash := sha256.Sum256(fileData)
	hashStr := hex.EncodeToString(hash[:])

	evidence := &Evidence{
		ID:          fmt.Sprintf("pcap-%d", time.Now().UnixNano()),
		Type:        EvidenceTypePcap,
		Timestamp:   time.Now(),
		CollectedBy: es.operator,
		Description: description,
		FilePath:    pcapPath,
		FileHash:    hashStr,
		FileSize:    fileInfo.Size(),
		Encrypted:   false,
		Metadata: map[string]interface{}{
			"original_path": pcapPath,
			"file_name":     filepath.Base(pcapPath),
		},
		ChainOfCustody: []CustodyEntry{
			{
				Timestamp:   time.Now(),
				Operator:    es.operator,
				Action:      "collected",
				Description: "PCAP file captured",
			},
		},
	}

	signature := ed25519.Sign(es.privateKey, fileData[:min(len(fileData), 1024*1024)])
	evidence.Signature = hex.EncodeToString(signature)
	evidence.SignatureMethod = "ed25519"

	if err := es.persistEvidence(evidence, nil); err != nil {
		return nil, err
	}

	return evidence, nil
}

func (es *EvidenceStore) persistEvidence(evidence *Evidence, data []byte) error {
	evidenceJSON, err := json.Marshal(evidence)
	if err != nil {
		return fmt.Errorf("failed to marshal evidence: %w", err)
	}

	if err := es.store.SaveScanResult(&store.ScanResult{
		ID:        evidence.ID,
		Timestamp: evidence.Timestamp,
		Status:    "stored",
		Metadata: map[string]interface{}{
			"evidence": string(evidenceJSON),
		},
	}); err != nil {
		return fmt.Errorf("failed to store evidence: %w", err)
	}

	if data != nil {
		dataPath := filepath.Join(es.basePath, fmt.Sprintf("%s.json", evidence.ID))
		if err := os.WriteFile(dataPath, data, 0640); err != nil {
			return fmt.Errorf("failed to write evidence data: %w", err)
		}
	}

	return nil
}

func (es *EvidenceStore) AddCustodyEntry(evidenceID string, action, description string) error {
	entry := CustodyEntry{
		Timestamp:   time.Now(),
		Operator:    es.operator,
		Action:      action,
		Description: description,
	}

	entryData, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal custody entry: %w", err)
	}

	signature := ed25519.Sign(es.privateKey, entryData)
	entry.Signature = hex.EncodeToString(signature)

	return nil
}

func (es *EvidenceStore) GenerateManifest(evidenceIDs []string) (*Manifest, error) {
	manifest := &Manifest{
		ID:        fmt.Sprintf("manifest-%d", time.Now().UnixNano()),
		CreatedAt: time.Now(),
		Version:   "1.0",
		Evidence:  make([]*Evidence, 0),
		SignedBy:  es.operator,
		Metadata:  make(map[string]interface{}),
	}

	for range evidenceIDs {
	}

	manifestData, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal manifest: %w", err)
	}

	hash := sha256.Sum256(manifestData)
	manifest.ManifestHash = hex.EncodeToString(hash[:])

	signature := ed25519.Sign(es.privateKey, manifestData)
	manifest.Signature = hex.EncodeToString(signature)

	return manifest, nil
}

func (es *EvidenceStore) VerifySignature(evidence *Evidence, data []byte) bool {
	if evidence.Signature == "" {
		return false
	}

	signatureBytes, err := hex.DecodeString(evidence.Signature)
	if err != nil {
		return false
	}

	return ed25519.Verify(es.publicKey, data, signatureBytes)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
