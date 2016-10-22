package main

// API result types
const ApiResultOk string = "ok"
const ApiResultError string = "error"

// API result messages
const ApiMessageLoginSuccess string = "Login successful"
const ApiMessageLogoutSuccess string = "Logout successful"
const ApiMessageUnauthorized string = "You must be logged in to view this page"
const ApiMessageInvalidToken string = "Invalid token"
const ApiMessageActivationSuccessful string = "Account activation successful"
const ApiMessageUnlockSuccessful string = "Account unlock successful"

// API Response instance
var ApiResponseLoginSuccess = ApiResponse{ApiResultOk, ApiMessageLoginSuccess}
var ApiResponseUnauthorized = ApiResponse{ApiResultError, ApiMessageUnauthorized}
