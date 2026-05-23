package analyzers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/overwatch/scanner-engine/internal/finding"
)

type DependencyAuditor struct {
	CacheDir string
}

func init() {
	Register(&DependencyAuditor{
		CacheDir: filepath.Join(os.TempDir(), "overwatch-cache"),
	})
}

func (a *DependencyAuditor) SupportedLanguages() []string {
	