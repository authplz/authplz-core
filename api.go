package main

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
const ApiMessageUnauthorized string = "You must be logged in to view this page"
const ApiMessageInvalidToken string = "Invalid token"
const ApiMessageActivationSuccessful string = "Activation Successful"

// API Response instance
var ApiResponseLoginSuccess = ApiResponse{ApiResultOk, ApiMessageLoginSuccess}
var ApiResponseUnauthorized = ApiResponse{ApiResultError, ApiMessageUnauthorized}



