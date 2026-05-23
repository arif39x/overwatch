package scannerengine

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewSecureTransport_RejectsSelfSigned(t *testing.T) {
	