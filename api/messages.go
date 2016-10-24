package api

// Common API response object
type ApiResponse struct {
    Result  string
    Message string
}

// API result types
const ApiResultOk string = "ok"
const ApiResultError string = "error"

// API result messages
const ApiMessageLoginSuccess string = "Login successful"
const ApiMessageLogoutSuccess string = "Logout successful"
const ApiMessageActivationSuccessful string = "Account activation successful"
const ApiMessageUnlockSuccessful string = "Account unlock successful"

const ApiMessageUnauthorized string = "You must be logged in to view this page"
const ApiMessageInvalidToken string = "Invalid token"
const ApiMessageInternalError string = "Internal server error"

// API Response instances
var ApiResponseLoginSuccess = ApiResponse{ApiResultOk, ApiMessageLoginSuccess}
var ApiResponseLogoutSuccess = ApiResponse{ApiResultOk, ApiMessageLogoutSuccess}
var ApiResponseActivationSuccessful = ApiResponse{ApiResultOk, ApiMessageActivationSuccessful}
var ApiResponseUnlockSuccessful = ApiResponse{ApiResultOk, ApiMessageUnlockSuccessful}

var ApiResponseUnauthorized = ApiResponse{ApiResultError, ApiMessageUnauthorized}
var ApiResponseInvalidToken = ApiResponse{ApiResultError, ApiMessageInvalidToken}
var ApiResponseInternalError = ApiResponse{ApiResultError, ApiMessageInternalError}
