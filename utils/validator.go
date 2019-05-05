package utils

import "gopkg.in/go-playground/validator.v9"

// Initializes a go-playground.validator to validate input JSON based on struct tags.
var validate *validator.Validate

func init() {
	validate = validator.New()
}

// ValidateStruct validates the given struct based on the struct tags
// added to the fields. If some field of the struct doesn't fulfill the
// validation requirements an error is returned.
func ValidateStruct(v interface{}) error {
	return validate.Struct(v)
}
