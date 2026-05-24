package compiler

import (
	"fmt"
	"strings"
)


type TokenType int

const (
	TokenError TokenType = iota
	TokenEOF
	TokenIdentifier
	TokenString
	TokenFind
	TokenWhere
	TokenSource
	TokenSink
	TokenSanitized
	TokenNot
	TokenAnd
	TokenLParen
	TokenRParen
	TokenEquals
	TokenArrow
	TokenComma
)


type Token struct {
	Type  TokenType
	Value string
}


type NodeSelector struct {
	Type       string            
	Attributes map[string]string 
	Negated    bool
}


type Query struct {
	VulnClass string
	Target    string
	Sources   []NodeSelector
	Sinks     []NodeSelector
	Filters   []NodeSelector
	Language  string
}


type Lexer struct {
	input  string
	pos    int
	tokens []Token
}

func NewLexer(input string) *Lexer {
	return &Lexer{input: input}
}

func (l *Lexer) Tokenize() []Token {
	for l.pos < len(l.input) {
		char := l.input[l.pos]

		switch {
		case isSpace(char):
			l.pos++
		case isAlpha(char):
			l.lexIdentifier()
		case char == '"':
			l.lexString()
		case char == '(':
			l.addToken(TokenLParen, "(")
			l.pos++
		case char == ')':
			l.addToken(TokenRParen, ")")
			l.pos++
		case char == '=':
			l.addToken(TokenEquals, "=")
			l.pos++
		case char == '-':
			if l.pos+1 < len(l.input) && l.input[l.pos+1] == '>' {
				l.addToken(TokenArrow, "->")
				l.pos += 2
			} else {
				l.pos++ 
			}
		case char == '!':
			l.addToken(TokenNot, "!")
			l.pos++
		case char == ',':
			l.addToken(TokenComma, ",")
			l.pos++
		default:
			l.pos++
		}
	}
	l.addToken(TokenEOF, "")
	return l.tokens
}

func (l *Lexer) lexIdentifier() {
	start := l.pos
	for l.pos < len(l.input) && (isAlpha(l.input[l.pos]) || isDigit(l.input[l.pos])) {
		l.pos++
	}
	val := l.input[start:l.pos]
	upper := strings.ToUpper(val)

	switch upper {
	case "FIND":
		l.addToken(TokenFind, val)
	case "WHERE":
		l.addToken(TokenWhere, val)
	case "SOURCE":
		l.addToken(TokenSource, val)
	case "SINK":
		l.addToken(TokenSink, val)
	case "SANITIZED":
		l.addToken(TokenSanitized, val)
	case "NOT":
		l.addToken(TokenNot, val)
	case "AND":
		l.addToken(TokenAnd, val)
	default:
		l.addToken(TokenIdentifier, val)
	}
}

func (l *Lexer) lexString() {
	l.pos++ 
	start := l.pos
	for l.pos < len(l.input) && l.input[l.pos] != '"' {
		l.pos++
	}
	val := l.input[start:l.pos]
	l.addToken(TokenString, val)
	l.pos++ 
}

func (l *Lexer) addToken(t TokenType, val string) {
	l.tokens = append(l.tokens, Token{Type: t, Value: val})
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }


type Parser struct {
	tokens []Token
	pos    int
}

func NewParser(tokens []Token) *Parser {
	return &Parser{tokens: tokens}
}

func (p *Parser) Parse() (*Query, error) {
	query := &Query{}

	if p.peek().Type != TokenFind {
		return nil, fmt.Errorf("expected FIND, got %v", p.peek().Value)
	}
	p.next() 

	if p.peek().Type != TokenIdentifier {
		return nil, fmt.Errorf("expected target identifier, got %v", p.peek().Value)
	}
	query.Target = p.next().Value

	if p.peek().Type != TokenWhere {
		return nil, fmt.Errorf("expected WHERE, got %v", p.peek().Value)
	}
	p.next() 

	for p.peek().Type != TokenEOF {
		token := p.peek()
		switch token.Type {
		case TokenSource, TokenSink, TokenSanitized, TokenNot:
			selector, err := p.parseSelector()
			if err != nil {
				return nil, err
			}
			switch selector.Type {
			case "source":
				query.Sources = append(query.Sources, selector)
			case "sink":
				query.Sinks = append(query.Sinks, selector)
			case "sanitized":
				query.Filters = append(query.Filters, selector)
			}
		case TokenArrow:
			p.next() 
		case TokenAnd:
			p.next() 
		case TokenIdentifier:
			if strings.ToUpper(token.Value) == "LANG" {
				p.next()
				if p.peek().Type == TokenEquals {
					p.next()
					if p.peek().Type == TokenString {
						query.Language = p.next().Value
					}
				}
			} else {
				p.next()
			}
		default:
			p.next()
		}
	}

	return query, nil
}

func (p *Parser) parseSelector() (NodeSelector, error) {
	sel := NodeSelector{Attributes: make(map[string]string)}
	if p.peek().Type == TokenNot {
		sel.Negated = true
		p.next()
	}

	token := p.next()
	switch token.Type {
	case TokenSource:
		sel.Type = "source"
	case TokenSink:
		sel.Type = "sink"
	case TokenSanitized:
		sel.Type = "sanitized"
	default:
		return sel, fmt.Errorf("expected selector type, got %v", token.Value)
	}

	if p.peek().Type == TokenLParen {
		p.next()
		for p.peek().Type != TokenRParen && p.peek().Type != TokenEOF {
			attrName := p.next().Value
			if p.peek().Type != TokenEquals {
				return sel, fmt.Errorf("expected =, got %v", p.peek().Value)
			}
			p.next()
			attrVal := p.next().Value
			sel.Attributes[attrName] = attrVal

			if p.peek().Type == TokenComma {
				p.next()
			}
		}
		p.next() 
	}

	return sel, nil
}

func (p *Parser) peek() Token {
	if p.pos >= len(p.tokens) {
		return Token{Type: TokenEOF}
	}
	return p.tokens[p.pos]
}

func (p *Parser) next() Token {
	t := p.peek()
	p.pos++
	return t
}


func (ns *NodeSelector) MatchNode(nodeText string, nodeKind string) bool {
	matches := true
	if name, ok := ns.Attributes["name"]; ok {
		if name != nodeText {
			matches = false
		}
	}
	if kind, ok := ns.Attributes["kind"]; ok {
		if kind != nodeKind {
			matches = false
		}
	}
	if ns.Negated {
		return !matches
	}
	return matches
}


func Compile(oql string) (*Query, error) {
	lexer := NewLexer(oql)
	tokens := lexer.Tokenize()
	parser := NewParser(tokens)
	return parser.Parse()
}


type Rule struct {
	ID         string `yaml:"id"`
	Language   string `yaml:"language"`
	Kind       string `yaml:"kind"`
	Identifier string `yaml:"identifier"`
	VulnClass  string `yaml:"vuln_class,omitempty"`
}
