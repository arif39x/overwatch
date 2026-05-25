package sourcecode

import (
	sitter "github.com/smacker/go-tree-sitter"
)

type SemanticData struct {
	SymbolTable *SymbolTable
	CallGraph   *CallGraph
	Failed      bool
	Warning     string
}

func ExtractSemantics(files []*File) {
	for _, f := range files {
		if f.AST == nil {
			continue
		}
		data := extractFileSemantics(f)
		f.Semantics = data
	}
}

func extractFileSemantics(f *File) *SemanticData {
	st := NewSymbolTable(f.Path, f.Language)
	cg := NewCallGraph()

	switch f.Language {
	case "go":
		extractGoSemantics(f.AST, f.Content, st, cg)
	case "java":
		extractJavaSemantics(f.AST, f.Content, st, cg)
	default:
		return &SemanticData{
			SymbolTable: st,
			CallGraph:   cg,
			Warning:     "no semantic adapter for language: " + f.Language,
		}
	}

	return &SemanticData{
		SymbolTable: st,
		CallGraph:   cg,
	}
}

func extractGoSemantics(n *sitter.Node, source []byte, st *SymbolTable, cg *CallGraph) {
	var visit func(*sitter.Node, string)
	visit = func(node *sitter.Node, currentFunction string) {
		switch node.Type() {
		case "import_declaration":
			for i := 0; i < int(node.ChildCount()); i++ {
				child := node.Child(i)
				if child.Type() == "import_spec" {
					path := ""
					alias := ""
					for j := 0; j < int(child.ChildCount()); j++ {
						specChild := child.Child(j)
						t := specChild.Type()
						if t == "interpreted_string_literal" || t == "raw_string_literal" {
							raw := specChild.Content(source)
							if len(raw) >= 2 {
								path = raw[1 : len(raw)-1]
							}
						}
						if t == "package_identifier" {
							alias = specChild.Content(source)
						}
					}
					if alias == "" {
						alias = path
					}
					st.AddImport(alias, path)
				}
			}

		case "function_declaration":
			nameNode := FindChildByType(node, "identifier")
			funcName := NodeText(nameNode, source)
			if funcName == "" {
				break
			}
			params := extractGoParamTypes(node, source)
			for _, p := range params {
				st.Add(&Symbol{
					Name:         p.name,
					DeclaredType: p.typ,
					Scope:        ScopeFunction,
					Kind:         KindParameter,
					ByteOffset:   int(p.nameNode.StartByte()),
					File:         st.File,
				})
			}
			body := FindChildByType(node, "block")
			if body != nil {
				visit(body, funcName)
			}

		case "method_declaration":
			recv := FindChildByType(node, "receiver")
			if recv != nil {
				for j := 0; j < int(recv.ChildCount()); j++ {
					rc := recv.Child(j)
					if rc.Type() == "parameter_declaration" {
						extractGoParam(rc, source, st, ScopeFunction, KindParameter)
					}
				}
			}
			nameNode := FindChildByType(node, "field_identifier")
			if nameNode == nil {
				nameNode = FindChildByType(node, "identifier")
			}
			funcName := NodeText(nameNode, source)
			params := extractGoParamTypes(node, source)
			for _, p := range params {
				st.Add(&Symbol{
					Name:         p.name,
					DeclaredType: p.typ,
					Scope:        ScopeFunction,
					Kind:         KindParameter,
					ByteOffset:   int(p.nameNode.StartByte()),
					File:         st.File,
				})
			}
			body := FindChildByType(node, "block")
			if body != nil {
				visit(body, funcName)
			}

		case "short_var_declaration":
			left := FindChildByType(node, "left")
			if left != nil {
				for j := 0; j < int(left.ChildCount()); j++ {
					id := left.Child(j)
					if id.Type() == "identifier" {
						st.Add(&Symbol{
							Name:       id.Content(source),
							DeclaredType: "",
							Scope:      ScopeBlock,
							Kind:       KindLocal,
							ByteOffset: int(id.StartByte()),
							File:       st.File,
						})
					}
				}
			}

		case "var_declaration":
			for j := 0; j < int(node.ChildCount()); j++ {
				spec := node.Child(j)
				if spec.Type() == "var_spec" {
					extractGoVarSpec(spec, source, st, ScopePackage)
				}
			}

		case "const_declaration":
			for j := 0; j < int(node.ChildCount()); j++ {
				spec := node.Child(j)
				if spec.Type() == "const_spec" {
					nameNode := FindChildByType(spec, "identifier")
					if nameNode != nil {
						st.Add(&Symbol{
							Name:       nameNode.Content(source),
							DeclaredType: "",
							Scope:      ScopePackage,
							Kind:       KindPackageLevel,
							ByteOffset: int(nameNode.StartByte()),
							File:       st.File,
						})
					}
				}
			}

		case "type_declaration":
			for j := 0; j < int(node.ChildCount()); j++ {
				spec := node.Child(j)
				if spec.Type() == "type_spec" {
					nameNode := FindChildByType(spec, "type_identifier")
					if nameNode != nil {
						typeExpr := FindChildByType(spec, "struct_type")
						typeName := ""
						if typeExpr != nil {
							typeName = "struct"
						} else {
							typeExpr = FindChildByType(spec, "interface_type")
							if typeExpr != nil {
								typeName = "interface"
							} else {
								typeExpr = FindChildByType(spec, "type_identifier")
								if typeExpr != nil {
									typeName = typeExpr.Content(source)
								}
							}
						}
						st.Add(&Symbol{
							Name:         nameNode.Content(source),
							DeclaredType: typeName,
							Scope:        ScopePackage,
							Kind:         KindPackageLevel,
							ByteOffset:   int(nameNode.StartByte()),
							File:         st.File,
						})
					}
				}
			}

		case "block":
			for i := 0; i < int(node.ChildCount()); i++ {
				visit(node.Child(i), currentFunction)
			}

		case "expression_switch_statement", "if_statement", "for_statement", "range_clause":
			for i := 0; i < int(node.ChildCount()); i++ {
				visit(node.Child(i), currentFunction)
			}

		case "call_expression":
			if currentFunction != "" {
				funcNode := node.Child(0)
				if funcNode != nil {
					callee := funcNode.Content(source)
					cg.AddEdge(currentFunction, callee, false)
				}
			}

		default:
			if node.Type() == "parameter_declaration" {
				extractGoParam(node, source, st, ScopeFunction, KindParameter)
			}
		}
	}
	visit(n, "")
}

type goParam struct {
	name     string
	typ      string
	nameNode *sitter.Node
}

func extractGoParamTypes(node *sitter.Node, source []byte) []goParam {
	var params []goParam
	paramList := FindChildByType(node, "parameter_list")
	if paramList == nil {
		return params
	}
	for i := 0; i < int(paramList.ChildCount()); i++ {
		p := paramList.Child(i)
		if p.Type() == "parameter_declaration" {
			params = append(params, extractGoParamInfo(p, source))
		}
	}
	return params
}

func extractGoParamInfo(p *sitter.Node, source []byte) goParam {
	nameNode := FindChildByType(p, "identifier")
	typeNode := FindChildByType(p, "type_identifier")
	typeName := ""
	if typeNode != nil {
		typeName = typeNode.Content(source)
	}
	name := ""
	if nameNode != nil {
		name = nameNode.Content(source)
	}
	return goParam{name: name, typ: typeName, nameNode: nameNode}
}

func extractGoParam(p *sitter.Node, source []byte, st *SymbolTable, scope ScopeType, kind SymbolKind) {
	info := extractGoParamInfo(p, source)
	if info.name != "" {
		st.Add(&Symbol{
			Name:         info.name,
			DeclaredType: info.typ,
			Scope:        scope,
			Kind:         kind,
			ByteOffset:   int(info.nameNode.StartByte()),
			File:         st.File,
		})
	}
}

func extractGoVarSpec(spec *sitter.Node, source []byte, st *SymbolTable, scope ScopeType) {
	nameNode := FindChildByType(spec, "identifier")
	typeNode := FindChildByType(spec, "type_identifier")
	typeName := ""
	if typeNode != nil {
		typeName = typeNode.Content(source)
	}
	if nameNode != nil {
		st.Add(&Symbol{
			Name:         nameNode.Content(source),
			DeclaredType: typeName,
			Scope:        scope,
			Kind:         KindPackageLevel,
			ByteOffset:   int(nameNode.StartByte()),
			File:         st.File,
		})
	}
}

func extractJavaSemantics(n *sitter.Node, source []byte, st *SymbolTable, cg *CallGraph) {
	var visit func(*sitter.Node, string)
	visit = func(node *sitter.Node, currentMethod string) {
		switch node.Type() {
		case "import_declaration":
			path := ""
			for i := 0; i < int(node.ChildCount()); i++ {
				c := node.Child(i)
				if c.Type() == "scoped_identifier" || c.Type() == "identifier" {
					path = c.Content(source)
				}
			}
			if path != "" {
				st.AddImport(path, path)
			}

		case "class_declaration":
			nameNode := FindChildByType(node, "identifier")
			if nameNode != nil {
				st.Add(&Symbol{
					Name:       nameNode.Content(source),
					DeclaredType: "class",
					Scope:      ScopePackage,
					Kind:       KindPackageLevel,
					ByteOffset: int(nameNode.StartByte()),
					File:       st.File,
				})
			}
			body := FindChildByType(node, "class_body")
			if body != nil {
				visit(body, "")
			}

		case "method_declaration":
			nameNode := FindChildByType(node, "identifier")
			methodName := NodeText(nameNode, source)
			params := FindChildByType(node, "formal_parameters")
			if params != nil {
				for i := 0; i < int(params.ChildCount()); i++ {
					p := params.Child(i)
					if p.Type() == "formal_parameter" {
						pName := FindChildByType(p, "identifier")
						pType := FindChildByType(p, "type_identifier")
						typeName := NodeText(pType, source)
						if pName != nil {
							st.Add(&Symbol{
								Name:         pName.Content(source),
								DeclaredType: typeName,
								Scope:        ScopeFunction,
								Kind:         KindParameter,
								ByteOffset:   int(pName.StartByte()),
								File:         st.File,
							})
						}
					}
				}
			}
			body := FindChildByType(node, "block")
			if body != nil {
				visit(body, methodName)
			}

		case "variable_declaration":
			for i := 0; i < int(node.ChildCount()); i++ {
				v := node.Child(i)
				if v.Type() == "variable_declarator" {
					id := FindChildByType(v, "identifier")
					if id != nil {
						st.Add(&Symbol{
							Name:       id.Content(source),
							DeclaredType: "",
							Scope:      ScopeBlock,
							Kind:       KindLocal,
							ByteOffset: int(id.StartByte()),
							File:       st.File,
						})
					}
				}
			}

		case "block":
			for i := 0; i < int(node.ChildCount()); i++ {
				visit(node.Child(i), currentMethod)
			}

		case "method_invocation":
			if currentMethod != "" {
				nameNode := FindChildByType(node, "identifier")
				if nameNode != nil {
					callee := nameNode.Content(source)
					obj := FindChildByType(node, "object")
					if obj != nil {
						callee = obj.Content(source) + "." + callee
					}
					cg.AddEdge(currentMethod, callee, false)
				}
			}

		default:
			for i := 0; i < int(node.ChildCount()); i++ {
				visit(node.Child(i), currentMethod)
			}
		}
	}
	visit(n, "")
}
