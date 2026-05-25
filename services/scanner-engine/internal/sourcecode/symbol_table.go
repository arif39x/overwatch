package sourcecode

type ScopeType int

const (
	ScopePackage ScopeType = iota
	ScopeFunction
	ScopeBlock
)

type SymbolKind int

const (
	KindParameter SymbolKind = iota
	KindLocal
	KindPackageLevel
	KindField
)

type Symbol struct {
	Name         string
	DeclaredType string
	Scope        ScopeType
	Kind         SymbolKind
	ByteOffset   int
	File         string
}

type SymbolTable struct {
	Symbols  map[string]*Symbol
	Imports  map[string]string
	File     string
	Language string
}

func NewSymbolTable(file, lang string) *SymbolTable {
	return &SymbolTable{
		Symbols:  make(map[string]*Symbol),
		Imports:  make(map[string]string),
		File:     file,
		Language: lang,
	}
}

func (st *SymbolTable) Add(s *Symbol) {
	st.Symbols[s.Name] = s
}

func (st *SymbolTable) Lookup(name string) *Symbol {
	return st.Symbols[name]
}

func (st *SymbolTable) AddImport(alias, path string) {
	st.Imports[alias] = path
}

func (st *SymbolTable) ResolveImport(alias string) string {
	return st.Imports[alias]
}
