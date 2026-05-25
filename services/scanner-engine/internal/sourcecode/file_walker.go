package sourcecode

import (
	"os"
	"path/filepath"

	sitter "github.com/smacker/go-tree-sitter"
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
		
		content, _ := os.ReadFile(path)
		files = append(files, &File{
			Path:    path,
			Content: content,
		})
		return nil
	})
	return files, err
}
