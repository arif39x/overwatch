package sourcecode

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/bash"
	"github.com/smacker/go-tree-sitter/c"
	"github.com/smacker/go-tree-sitter/cpp"
	"github.com/smacker/go-tree-sitter/golang"
	"github.com/smacker/go-tree-sitter/java"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/kotlin"
	"github.com/smacker/go-tree-sitter/php"
	"github.com/smacker/go-tree-sitter/python"
	"github.com/smacker/go-tree-sitter/ruby"
	"github.com/smacker/go-tree-sitter/rust"
	"github.com/smacker/go-tree-sitter/scala"
	"github.com/smacker/go-tree-sitter/swift"
	"github.com/smacker/go-tree-sitter/typescript/tsx"
	"github.com/smacker/go-tree-sitter/typescript/typescript"
)

var skippedDirectories = map[string]struct{}{
	".git":         {},
	"node_modules": {},
	"testdata":     {},
	"vendor":       {},
}

var languageMap = map[string]*sitter.Language{
	".go":    golang.GetLanguage(),
	".py":    python.GetLanguage(),
	".js":    javascript.GetLanguage(),
	".jsx":   javascript.GetLanguage(),
	".ts":    typescript.GetLanguage(),
	".tsx":   tsx.GetLanguage(),
	".rs":    rust.GetLanguage(),
	".c":     c.GetLanguage(),
	".h":     c.GetLanguage(),
	".cpp":   cpp.GetLanguage(),
	".cc":    cpp.GetLanguage(),
	".cxx":   cpp.GetLanguage(),
	".hpp":   cpp.GetLanguage(),
	".java":  java.GetLanguage(),
	".rb":    ruby.GetLanguage(),
	".php":   php.GetLanguage(),
	".swift": swift.GetLanguage(),
	".kt":    kotlin.GetLanguage(),
	".scala": scala.GetLanguage(),
	".sh":    bash.GetLanguage(),
	".bash":  bash.GetLanguage(),
}

