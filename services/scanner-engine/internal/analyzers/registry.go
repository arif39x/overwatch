package analyzers

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/overwatch/scanner-engine/internal/finding"
	"github.com/overwatch/scanner-engine/internal/sourcecode"
)

var (
	registry []Analyzer
)

