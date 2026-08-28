package spdxkit

// The upstream parser is right-recursive for AND and OR and recursive for
// parentheses. These structural bounds complement the byte bound: a short,
// deeply nested expression must not be able to exhaust the process stack.
const (
	maxExpressionOperators = 1024
	maxExpressionNesting   = 128
	maxSatisfiesTerms      = 4096
)

func expressionWithinParseLimits(expression string) bool {
	operators := 0
	depth := 0
	for _, segment := range splitExpression(expression) {
		if segment.separator {
			for _, r := range segment.text {
				switch r {
				case '(':
					depth++
					if depth > maxExpressionNesting {
						return false
					}
				case ')':
					if depth > 0 {
						depth--
					}
				}
			}
			continue
		}
		if segment.text == "AND" || segment.text == "OR" {
			operators++
			if operators > maxExpressionOperators {
				return false
			}
		}
	}
	return true
}

// satisfiesWithinExpansionLimit calculates the number of conjunctive terms
// the upstream Satisfies implementation would materialize. OR adds term
// counts and AND multiplies them, so a small input can otherwise cause an
// exponential allocation. Malformed shapes are left for the parser to report.
func satisfiesWithinExpansionLimit(expression string) bool {
	values := make([]int, 0, 16)
	operators := make([]byte, 0, 16)
	skipException := false

	apply := func() (wellFormed, withinLimit bool) {
		if len(operators) == 0 || len(values) < 2 {
			return false, true
		}
		op := operators[len(operators)-1]
		operators = operators[:len(operators)-1]
		right := values[len(values)-1]
		left := values[len(values)-2]
		values = values[:len(values)-2]
		var terms int
		switch op {
		case '&':
			if left > maxSatisfiesTerms/right {
				return true, false
			}
			terms = left * right
		case '|':
			if left > maxSatisfiesTerms-right {
				return true, false
			}
			terms = left + right
		default:
			return false, true
		}
		values = append(values, terms)
		return true, true
	}

	precedence := func(op byte) int {
		if op == '&' {
			return 2
		}
		if op == '|' {
			return 1
		}
		return 0
	}

	for _, segment := range splitExpression(expression) {
		if segment.separator {
			for _, r := range segment.text {
				switch r {
				case '(':
					operators = append(operators, '(')
				case ')':
					for len(operators) > 0 && operators[len(operators)-1] != '(' {
						wellFormed, withinLimit := apply()
						if !withinLimit {
							return false
						}
						if !wellFormed {
							return true
						}
					}
					if len(operators) == 0 {
						return true
					}
					operators = operators[:len(operators)-1]
				}
			}
			continue
		}

		switch segment.text {
		case "WITH":
			skipException = true
		case "AND", "OR":
			if skipException {
				return true
			}
			op := byte('|')
			if segment.text == "AND" {
				op = '&'
			}
			for len(operators) > 0 && precedence(operators[len(operators)-1]) >= precedence(op) {
				wellFormed, withinLimit := apply()
				if !withinLimit {
					return false
				}
				if !wellFormed {
					return true
				}
			}
			operators = append(operators, op)
		default:
			if skipException {
				skipException = false
				continue
			}
			values = append(values, 1)
		}
	}

	if skipException {
		return true
	}
	for len(operators) > 0 {
		if operators[len(operators)-1] == '(' {
			return true
		}
		wellFormed, withinLimit := apply()
		if !withinLimit {
			return false
		}
		if !wellFormed {
			return true
		}
	}
	return len(values) != 1 || values[0] <= maxSatisfiesTerms
}
