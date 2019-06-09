package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/roberveral/mimir/utils"

	log "github.com/sirupsen/logrus"
)

// Action represents a possible action performed by a controller,
// usually maped to REST operations.
type Action func(rw http.ResponseWriter, r *http.Request) error

// ErrorHandler is a method which transforms from an error to the associated
// HTTP Status Code.
type ErrorHandler func(err error) int

// Controller is the base type for API controllers. Implementations embed this type
// so the Perfotm method is available.
type Controller struct {
	errorHandler ErrorHandler
}

// NewController creates a new Controller. A Controller is able to perform an action
// so it can be mapped to an HTTP route. It uses the given error handler to obtain
// the appropriate status code in case of error.
func NewController(eh ErrorHandler) Controller {
	return Controller{eh}
}

// Perform obtains the function to handle a HTTP request executing the given action. If
// the actions returns an error, it is mapped to the aproppiate status code.
func (c *Controller) Perform(a Action) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		user, _ := utils.GetAuthenticatedUserFromContext(r.Context())
		log.Infof("%s\t\t%s\t\t%s\t\t%s", r.Method, r.RequestURI, r.RemoteAddr, user)
		if err := a(rw, r); err != nil {
			statusCode := http.StatusInternalServerError
			if c.errorHandler != nil {
				statusCode = c.errorHandler(err)
			}
			log.Errorf("Error while processing request: %v. Status Code: %d", err, statusCode)
			SendErrorResponse(statusCode, rw, err)
		}
	})
}

// errorResponse is the model for returning errors as JSON.
type errorResponse struct {
	ErrorType   string `json:"error_type,omitempty"`
	ErrorReason string `json:"error_reason,omitempty"`
}

// SendErrorResponse writes an error in the HTTP response using the errorResponse struct.
func SendErrorResponse(statusCode int, rw http.ResponseWriter, err error) error {
	encoder := json.NewEncoder(rw)

	response := &errorResponse{fmt.Sprintf("%T", err), err.Error()}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(statusCode)
	return encoder.Encode(response)
}

// DecodeAndValidateJSON decodes the JSON in the input reader into the given type and
// validates the struct based on its struct tags.
func DecodeAndValidateJSON(r io.Reader, v interface{}) error {
	if err := json.NewDecoder(r).Decode(v); err != nil {
		return nil
	}

	return utils.ValidateStruct(v)
}
