package core

import (
	"log"

	"github.com/ryankurte/authplz/lib/api"
)

// SecondFactorCompleted handles completion of a 2fa provider
func (coreModule *Controller) SecondFactorCompleted(userid, action string) {
	log.Printf("CoreModule.SecondFactorCompleted for user %s action %s", userid, action)
}

// CheckSecondFactors Determine whether a second factor is required for a user
// This returns a bool indicating whether 2fa is required, and a map of the available 2fa mechanisms
func (coreModule *Controller) CheckSecondFactors(userid string) (bool, map[string]bool) {
	availableHandlers := make(map[string]bool)
	secondFactorRequired := false

	for key, handler := range coreModule.secondFactorHandlers {
		supported := handler.IsSupported(userid)
		if supported {
			secondFactorRequired = true
		}
		availableHandlers[key] = supported
	}

	return secondFactorRequired, availableHandlers
}

// HandleToken Handles a token string for a given user
// Returns accepted bool and error in case of failure
func (coreModule *Controller) HandleToken(userid string, user interface{}, tokenString string) (bool, error) {
	action, err := coreModule.tokenControl.ValidateToken(userid, tokenString)
	if err != nil {
		log.Printf("CoreModule.Login: token validation failed %s\n", err)
		return false, nil
	}

	// Locate token handler
	tokenHandler, ok := coreModule.tokenHandlers[*action]
	if !ok {
		log.Printf("CoreModule.HandleToken: no token handler found for action %s\n", action)
		return false, err
	}

	// Execute token action
	err = tokenHandler.HandleToken(userid, *action)
	if err != nil {
		log.Printf("CoreModule.HandleToken: token action %s handler error %s\n", action, err)
		return false, err
	}

	log.Printf("CoreModule.HandleToken: token action %v executed for user %s\n", *action, userid)
	return true, nil
}

// HandleRecoveryToken handles a password reset or account recovery token
func (coreModule *Controller) HandleRecoveryToken(email string, tokenString string) (bool, interface{}, error) {

	// Load user
	u, err := coreModule.userControl.GetUserByEmail(email)
	if err != nil {
		log.Printf("CoreModule.HandleRecoveryToken: fetching user failed %s\n", err)
		return false, nil, nil
	}
	user := u.(UserInterface)

	// Validate token
	action, err := coreModule.tokenControl.ValidateToken(user.GetExtID(), tokenString)
	if err != nil {
		log.Printf("CoreModule.HandleRecoveryToken: token validation failed %s\n", err)
		return false, nil, nil
	}

	// Check for correct action
	if *action != api.TokenActionRecovery {
		return false, nil, nil
	}

	return true, u, nil
}

// PreLogin Runs bound login handlers to accept user logins
func (coreModule *Controller) PreLogin(u interface{}) (bool, error) {
	for key, handler := range coreModule.preLogin {
		ok, err := handler.PreLogin(u)
		if err != nil {
			log.Printf("CoreModule.LoginHandlers: error in handler %s (%s)", key, err)
			return false, err
		}
		if !ok {
			log.Printf("CoreModule.LoginHandlers: login blocked by handler %s", key)
			return false, nil
		}
	}

	return true, nil
}

// PostLoginSuccess Runs bound post login success handlers
func (coreModule *Controller) PostLoginSuccess(u interface{}) error {
	for key, handler := range coreModule.postLoginSuccess {
		err := handler.PostLoginSuccess(u)
		if err != nil {
			log.Printf("CoreModule.PostLoginSuccess: error in handler %s (%s)", key, err)
			return err
		}
	}
	return nil
}

// PostLoginFailure Runs bound post login failure handlers
func (coreModule *Controller) PostLoginFailure(u interface{}) error {
	for key, handler := range coreModule.postLoginFailure {
		err := handler.PostLoginFailure(u)
		if err != nil {
			log.Printf("CoreModule.PostLoginFailure: error in handler %s (%s)", key, err)
			return err
		}
	}
	return nil
}


// PostLoginFailure Runs bound post login failure handlers
func (coreModule *Controller) PasswordResetStart(email string) error {
	
	
	return nil
}
