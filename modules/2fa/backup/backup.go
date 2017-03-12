package backup

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
)

import (
	//"github.com/ryankurte/mnemonic"
	"golang.org/x/crypto/bcrypt"
)

const (
	recoveryKeyLen   = 128 / 8
	numRecoveryKeys  = 5
	backupHashRounds = 12
)

// Controller Backup code controller instance
type Controller struct {
	issuerName  string
	backupStore Storer
}

// NewController creates a new backup code controller
// Backup tokens are issued with an associated issuer name to assist with user identification of codes.
// A Storer provides underlying storage to the backup code module
func NewController(issuerName string, backupStore Storer) *Controller {
	return &Controller{
		issuerName:  issuerName,
		backupStore: backupStore,
	}
}

// CodeResponse is the backup code response object returned when codes are created
type CodeResponse struct {
	Names []string
	Keys  []string
}

// CreateCodes creates a set of backup codes for a user
// TODO: should this erase existing codes?
func (bc *Controller) CreateCodes(userid string) (*CodeResponse, error) {
	rawCodes := make([]string, numRecoveryKeys)

	// Generate raw codes
	for i := range rawCodes {
		buf := make([]byte, recoveryKeyLen)
		n, err := rand.Read(buf)
		if err != nil {
			return nil, err
		}
		if n != recoveryKeyLen {
			return nil, fmt.Errorf("BackupController.CreateCodes entropy error")
		}
		rawCodes[i] = base64.URLEncoding.EncodeToString(buf)
	}

	// TODO: build friendly mnemonics (code name and data)
	mnemonicKeys := make([]string, numRecoveryKeys)
	mnemonicNames := make([]string, numRecoveryKeys)

	// Hash raw codes for storage
	hashedCodes := make([]string, numRecoveryKeys)
	for i, code := range rawCodes {
		hashed, err := bcrypt.GenerateFromPassword([]byte(code), backupHashRounds)
		if err != nil {
			return nil, err
		}
		hashedCodes[i] = string(hashed)
	}

	// Save to database
	for i := range hashedCodes {
		_, err := bc.backupStore.AddBackupCode(userid, mnemonicNames[i], hashedCodes[i])
		if err != nil {
			return nil, err
		}
	}

	// Create Response for client
	rc := CodeResponse{
		Names: mnemonicNames,
		Keys:  mnemonicKeys,
	}

	return &rc, nil
}

// IsSupported checks whether the backup code method is supported
func (bc *Controller) IsSupported(userid string) bool {
	// Fetch codes for a user
	codes, err := bc.backupStore.GetBackupCodes(userid)
	if err != nil {
		log.Printf("BackupController.IsSupported error fetching codes (%s)", err)
		return false
	}

	// Check for an active code
	// TODO: this means that when all active codes have been used this method will be disabled
	// is this the desired behaviour? Could we warn a user prior to disabling it?
	available := false
	for _, c := range codes {
		code := c.(Code)
		if !code.IsUsed() {
			available = true
		}
	}

	return available
}

// ValidateName validates a code name
// This is intended to be checked periodically when using other login mechanisms
// to ensure user still has access to recovery codes
func (bc *Controller) ValidateName(userid string, name string) (bool, error) {
	// Fetch associated codes with for the provided user
	codes, err := bc.backupStore.GetBackupCodes(userid)
	if err != nil {
		log.Println(err)
		return false, err
	}

	// Check provided code against enabled codes
	for _, c := range codes {
		code := c.(Code)
		if (code.GetName() == name) && !code.IsUsed() {
			return true, nil
		}
	}

	// No matching code found
	return false, nil
}

// ValidateCode validates a backup code use
func (bc *Controller) ValidateCode(userid string, code string) (bool, error) {
	// Fetch associated codes with for the provided user

	// Translate mnemonic form to bytes

	// Check provided code against enabled codes

	// Mark code as disabled

	return false, nil
}
