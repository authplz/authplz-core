/*
 * (2fa) Backup Code Module tests
 * This defines the tests for the 2fa Backup Code module
 *
 * AuthPlz Project (https://github.com/authplz/authplz-core)
 * Copyright 2017 Ryan Kurte
 */

package backup

import (
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/authplz/authplz-core/lib/test"
)

type BackupTest struct {
	name string
	f    func(t *testing.T, bc *Controller)
}

var tests = []BackupTest{}

func TestBackupModule(t *testing.T) {

	userID := "1"
	var keys = make([]BackupKey, 0)
	var codes *CreateResponse

	// Mocks don't work unless ctrl is instantiated in every subtest (with the appropriate t)
	// There /has/ to be a way of refactoring this, but, idk what it is :-/

	t.Run("Create backup token", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockStore := NewMockStorer(ctrl)
		bc := NewController("Test Service", mockStore, &test.MockEventEmitter{})

		code, err := bc.generateCode(recoveryKeyLen)
		assert.Nil(t, err)
		assert.NotNil(t, code)
	})

	t.Run("Create backup tokens for user", func(t *testing.T) {
		var err error
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockStore := NewMockStorer(ctrl)
		bc := NewController("Test Service", mockStore, &test.MockEventEmitter{})

		mockStore.EXPECT().AddBackupToken(userID, gomock.Any(), gomock.Any()).Times(numRecoveryKeys).Do(func(userID, name, key string) {
			keys = append(keys, BackupKey{userID, name, key})
		})

		codes, err = bc.CreateCodes(userID)
		assert.Nil(t, err)
		assert.Len(t, keys, numRecoveryKeys)
		assert.Len(t, codes.Tokens, numRecoveryKeys)
	})

	t.Run("Validate backup tokens for user", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockStore := NewMockStorer(ctrl)
		bc := NewController("Test Service", mockStore, &test.MockEventEmitter{})

		code := strings.Join([]string{codes.Tokens[0].Name, codes.Tokens[0].Code}, " ")

		mockCode := NewMockCode(ctrl)
		mockCode.EXPECT().GetName().Return(codes.Tokens[0].Name)
		mockCode.EXPECT().IsUsed().Return(false)
		mockCode.EXPECT().GetHashedSecret().Return(keys[0].Hash)
		mockCode.EXPECT().SetUsed()

		mockStore.EXPECT().GetBackupTokenByName(userID, codes.Tokens[0].Name).Return(mockCode, nil)

		mockCode.EXPECT().GetName().Return(codes.Tokens[0].Name)
		mockStore.EXPECT().UpdateBackupToken(mockCode)

		ok, err := bc.ValidateCode(userID, code)
		assert.Nil(t, err)

		if !ok {
			t.Errorf("Backup code validation failed (expected success) code: %s", code)
		}
	})

	t.Run("Backup codes can only be validated once", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockStore := NewMockStorer(ctrl)
		bc := NewController("Test Service", mockStore, &test.MockEventEmitter{})

		code := strings.Join([]string{codes.Tokens[0].Name, codes.Tokens[0].Code}, " ")

		ok, err := bc.ValidateCode(userID, code)
		assert.Nil(t, err)
		if ok {
			t.Errorf("Backup code validation succeeded (expected failure)")
		}
	})

}
