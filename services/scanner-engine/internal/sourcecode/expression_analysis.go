package sourcecode

import (
	sitter "github.com/smacker/go-tree-sitter"
)

func NodeHasType(n *sitter.Node, typeName string) bool {
	return n.Type() == typeName
}

func FindChildByType(n *sitter.Node, typeName string) *sitter.Node {
	for i := 0; i < int(n.ChildCount()); i++ {
		c := n.Child(i)
		if c.Type() == typeName {
			return c
		}
	}
	return nil
}

func FindAllChildrenByType(n *sitter.Node, typeName string) []*sitter.Node {
	var result []*sitter.Node
	for i := 0; i < int(n.ChildCount()); i++ {
		c := n.Child(i)
		if c.Type() == typeName {
			result = append(result, c)
		}
	}
	return result
}

func CollectDescendantsByType(n *sitter.Node, typeName string) []*sitter.Node {
	var result []*sitter.Node
	var visit func(*sitter.Node)
	visit = func(node *sitter.Node) {
		if node.Type() == typeName {
			result = append(result, node)
		}
		for i := 0; i < int(node.ChildCount()); i++ {
			visit(node.Child(i))
		}
	}
	visit(n)
	return result
}

func NodeText(n *sitter.Node, source []byte) string {
	if n == nil {
		return ""
	}
	return n.Content(source)
}

func NodeStartByte(n *sitter.Node) int {
	return int(n.StartByte())
}
