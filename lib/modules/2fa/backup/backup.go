/*
 * (2fa) Backup Code Module Controller
 * This defines the controller for the 2fa Backup Code module
 *
 * AuthPlz Project (https://github.com/authplz/authplz-core)
 * Copyright 2017 Ryan Kurte
 */

package backup

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/authplz/authplz-core/lib/events"

	"github.com/NebulousLabs/entropy-mnemonics"
	"golang.org/x/crypto/bcrypt"
)

const (
	recoveryKeyLen   = 128 / 8
	recoveryNameLen  = 3
	numRecoveryKeys  = 5
	backupHashRounds = 12
)

// Controller Backup code controller instance
// The backup code controller generates and parses mnemonic backup codes for 2fa use
// These codes can be registered and used in the same manner as any other 2fa component.
type Controller struct {
	issuerName  string
	backupStore Storer
	emitter     events.EventEmitter
}

// NewController creates a new backup code controller
// Backup tokens are issued with an associated issuer name to assist with user identification of codes.
// A Storer provides underlying storage to the backup code module
func NewController(issuerName string, backupStore Storer, emitter events.EventEmitter) *Controller {
	return &Controller{
		issuerName:  issuerName,
		backupStore: backupStore,
		emitter:     emitter,
	}
}

func cryptoBytes(size int) ([]byte, error) {
	data := make([]byte, size)
	n, err := rand.Read(data)
	if err != nil {
		return data, err
	}
	if n != size {
		return data, fmt.Errorf("BackupController.CreateCodes entropy error")
	}
	return data, nil
}

// BackupKey structure for API use
type BackupKey struct {
	// Mnemonic key name
	Name string
	// Mnemonic key code
	Code string
	// Key Hash
	Hash string
}

// CodeResponse is the backup code response object returned when codes are created
type CodeResponse struct {
	Keys []BackupKey
}

func (bc *Controller) generateCode(len int) (*BackupKey, error) {
	code, err := cryptoBytes(len)
	if err != nil {
		return nil, err
	}

	name, err := cryptoBytes(recoveryNameLen)
	if err != nil {
		return nil, err
	}

	// Generate mnemonic codes
	mnemonicCode, err := mnemonics.ToPhrase(code, mnemonics.English)
	if err != nil {
		return nil, err
	}

	mnemonicName, err := mnemonics.ToPhrase(name, mnemonics.English)
	if err != nil {
		return nil, err
	}

	// Generate hashes
	hash, err := bcrypt.GenerateFromPassword([]byte(code), backupHashRounds)
	if err != nil {
		return nil, err
	}

	key := BackupKey{mnemonicName.String(), mnemonicCode.String(), string(hash)}

	return &key, nil
}

type CreateResponse struct {
	Service string
	Tokens  []BackupKey
}

// CreateCodes creates a set of backup codes for a user
// TODO: should this erase existing codes?
func (bc *Controller) CreateCodes(userid string) (*CreateResponse, error) {
	keys := make([]BackupKey, numRecoveryKeys)

	// Generate backup keys
	for i := range keys {
		key, err := bc.generateCode(recoveryKeyLen)
		if err != nil {
			return nil, err
		}

		keys[i] = *key
	}

	// Save to database
	for _, key := range keys {
		_, err := bc.backupStore.AddBackupToken(userid, key.Name, key.Hash)
		if err != nil {
			return nil, err
		}
	}

	resp := CreateResponse{bc.issuerName, keys}

	data := make(map[string]string)
	bc.emitter.SendEvent(events.NewEvent(userid, events.Event2faBackupCodesAdded, data))

	return &resp, nil
}

// IsSupported checks whether the backup code method is supported
func (bc *Controller) IsSupported(userid string) bool {
	// Fetch codes for a user
	codes, err := bc.backupStore.GetBackupTokens(userid)
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
	codes, err := bc.backupStore.GetBackupTokens(userid)
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

// ValidateCode validates a backup code use and marks the code as used
func (bc *Controller) ValidateCode(userid string, codeString string) (bool, error) {

	// Split codeString into words
	phrase := strings.Split(codeString, " ")

	// Fetch key name
	name := strings.Join(phrase[:recoveryNameLen], " ")

	// Translate mnemonic form to bytes
	mnemonicKey := strings.Join(phrase[recoveryNameLen:], " ")
	key, err := mnemonics.FromString(mnemonicKey, mnemonics.English)

	// Fetch associated codes with for the provided user
	c, err := bc.backupStore.GetBackupTokenByName(userid, name)
	if err != nil {
		log.Printf("Backup.ValidateCode datastore error: %s", err)
		return false, err
	}
	if c == nil {
		log.Printf("Backup.ValidateCode No matching backup token found")
		return false, nil
	}
	code := c.(Code)

	// Check code matches
	if (code.GetName() != name) || code.IsUsed() {
		log.Printf("Backup.ValidateCode code already used")
		return false, nil
	}

	// Check provided code against stored hash
	err = bcrypt.CompareHashAndPassword([]byte(code.GetHashedSecret()), key)
	if err != nil {
		log.Printf("Backup.ValidateCode mismatching secrets")
		return false, nil
	}

	// Mark code as disabled
	code.SetUsed()

	// Update code in database
	_, err = bc.backupStore.UpdateBackupToken(code)
	if err != nil {
		log.Printf("Backup.ValidateCode datastore error: %s", err)
		return false, err
	}

	data := make(map[string]string)
	data["Code Name"] = code.GetName()
	bc.emitter.SendEvent(events.NewEvent(userid, events.Event2faBackupCodesUsed, data))

	return true, nil
}

type BackupCode struct {
	Name      string
	Used      bool
	CreatedAt time.Time
	UsedAt    time.Time
}

// ListCodes fetches a list of the available backup codes
func (bc *Controller) ListCodes(userid string) ([]BackupCode, error) {
	// Fetch codes for a user
	codes, err := bc.backupStore.GetBackupTokens(userid)
	if err != nil {
		log.Printf("BackupController.IsSupported error fetching codes (%s)", err)
		return nil, errors.New("Backup Code Controller: internal error")
	}

	safeCodes := make([]BackupCode, len(codes))
	for i := range codes {
		code := codes[i].(Code)
		safeCodes[i] = BackupCode{
			Name:      code.GetName(),
			Used:      code.IsUsed(),
			UsedAt:    code.GetUsedAt(),
			CreatedAt: code.GetCreatedAt(),
		}
	}

	return safeCodes, nil
}
