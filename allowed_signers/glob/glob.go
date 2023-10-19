package glob

import (
	"database/sql"
	"fmt"
	"regexp"
	"strings"
)

func multiMatch(reg *regexp.Regexp, text string) sql.NullInt64 {
	result := reg.FindStringSubmatch(text)
	if result != nil {
		index := 0
		for i := 1; i < len(result); i++ {
			if result[i] != "" {
				index = i
				break
			}
		}
		return sql.NullInt64{
			Int64: int64(index - 1),
			Valid: true,
		}
	} else {
		return sql.NullInt64{
			Int64: 0,
			Valid: false,
		}
	}
}

func globToRegex(input string) string {
	subStrings := []string{""}
	// walk until we find a special character
	// check if escaped it is leave it but without \
	// if it is not escaped replace it with the regex equivalent
	l := len(input)
	var isSpecial bool
	for i := 0; i < l; i++ {
		switch input[i] {
		case '\\':
			if i != l {
				switch input[i+1] {
				case '*', '?':
					subStrings[len(subStrings)-1] += string(input[i+1])
					isSpecial = false
				default:
					subStrings[len(subStrings)-1] += "\\" + string(input[i])
					isSpecial = false
				}
				i++
			} else {
				subStrings[len(subStrings)-1] += "\\"
				isSpecial = false
			}
		case '*':
			subStrings[len(subStrings)-1] = regexp.QuoteMeta(subStrings[len(subStrings)-1])
			subStrings = append(subStrings, ".*")
			subStrings = append(subStrings, "")
			isSpecial = true
		case '?':
			subStrings[len(subStrings)-1] = regexp.QuoteMeta(subStrings[len(subStrings)-1])
			subStrings = append(subStrings, ".")
			subStrings = append(subStrings, "")
			isSpecial = true
		default:
			subStrings[len(subStrings)-1] += string(input[i])
			isSpecial = false
		}
	}
	if !isSpecial {
		subStrings[len(subStrings)-1] = regexp.QuoteMeta(subStrings[len(subStrings)-1])
	}

	return strings.Join(subStrings, "")
}

func GetListMatcher(patterns []string) (func(string) sql.NullString, error) {
	positivePatterns := make([]string, 0)
	negativePatterns := make([]string, 0)
	positivePatternsGlob := make([]string, 0)
	negativePatternsGlob := make([]string, 0)
	for _, pattern := range patterns {
		// ensure that the pattern list handles these matches
		// e.g. when [*, !foo] is passed, it should match everything except foo
		if pattern[0] == '!' {
			negativePatternsGlob = append(negativePatternsGlob, pattern)
			negativePatterns = append(negativePatterns, globToRegex(pattern[1:]))
		} else {
			positivePatternsGlob = append(positivePatternsGlob, pattern)
			positivePatterns = append(positivePatterns, globToRegex(pattern))
		}
	}
	var posReg string
	for _, pattern := range positivePatterns {
		posReg += "(^" + pattern + "$)|"
	}
	posReg = strings.TrimSuffix(posReg, "|")
	var negReg string
	for _, pattern := range negativePatterns {
		negReg += "(^" + pattern + "$)|"
	}
	negReg = strings.TrimSuffix(negReg, "|")

	p, err := regexp.Compile(posReg)
	if err != nil {
		return nil, fmt.Errorf("failed to compile positive regex: %w", err)
	}
	n, err := regexp.Compile(negReg)
	if err != nil {
		return nil, fmt.Errorf("failed to compile positive regex: %w", err)
	}
	return func(s string) sql.NullString {
		matched := multiMatch(p, s)
		negative := multiMatch(n, s)
		if matched.Valid {
			if negative.Valid {
				return sql.NullString{
					String: negativePatternsGlob[negative.Int64],
					Valid:  false,
				}
			}
			return sql.NullString{
				String: positivePatternsGlob[matched.Int64],
				Valid:  true,
			}
		} else {
			return sql.NullString{
				String: "",
				Valid:  false,
			}
		}
	}, nil
}
