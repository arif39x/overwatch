package sourcecode

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/golang"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/python"
	"github.com/smacker/go-tree-sitter/typescript/tsx"
	typescript "github.com/smacker/go-tree-sitter/typescript/typescript"
)

type File struct {
	Path      string
	Content   []byte
	Language  string
	AST       *sitter.Node
	Semantics *SemanticData
}

func Walk(root string) ([]*File, error) {
	var files []*File
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		f := &File{
			Path:    path,
			Content: content,
		}

		f.Language = detectLanguage(path)
		f.AST = parseAST(content, f.Language)

		files = append(files, f)
		return nil
	})
	return files, err
}

func detectLanguage(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".js", ".jsx":
		return "javascript"
	case ".ts":
		return "typescript"
	case ".tsx":
		return "tsx"
	case ".c", ".h":
		return "c"
	case ".cpp", ".cc", ".cxx", ".hpp":
		return "cpp"
	case ".java":
		return "java"
	case ".rs":
		return "rust"
	case ".php":
		return "php"
	case ".rb":
		return "ruby"
	case ".swift":
		return "swift"
	case ".kt", ".kts":
		return "kotlin"
	default:
		return ""
	}
}

func parseAST(content []byte, lang string) *sitter.Node {
	if lang == "" || len(content) == 0 {
		return nil
	}

	var language *sitter.Language
	switch lang {
	case "go":
		language = golang.GetLanguage()
	case "python":
		language = python.GetLanguage()
	case "javascript":
		language = javascript.GetLanguage()
	case "typescript":
		language = typescript.GetLanguage()
	case "tsx":
		language = tsx.GetLanguage()
	default:
		return nil
	}

	node, err := sitter.ParseCtx(context.Background(), content, language)
	if err != nil {
		return nil
	}
	return node
}
