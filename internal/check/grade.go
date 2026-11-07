package check

import "strings"

// Points per check. DMARC weighs most because it is the only control that
// tells receivers to act on SPF and DKIM failures.
const (
	spfPoints   = 30
	dkimPoints  = 25
	dmarcPoints = 45
)

// Grade converts a report into a 0-100 score and a letter grade.
func Grade(r Report) (int, string) {
	score := spfScore(r.SPF) + dkimScore(r.DKIM) + dmarcScore(r.DMARC)
	return score, letter(score)
}

func spfScore(s SPFResult) int {
	switch s.Status {
	case StatusPass:
		if s.All == "-all" {
			return spfPoints
		}
		return spfPoints - 5 // ~all
	case StatusWeak:
		return 10
	default:
		return 0
	}
}

func dkimScore(d DKIMResult) int {
	switch d.Status {
	case StatusPass:
		return dkimPoints
	case StatusWeak:
		return 12
	default:
		return 0
	}
}

func dmarcScore(d DMARCResult) int {
	var score int
	switch d.Policy {
	case "reject":
		score = dmarcPoints
	case "quarantine":
		score = 35
	case "none":
		score = 10
	default:
		return 0
	}
	if d.Status == StatusFail || d.Status == StatusError || d.Status == StatusMissing {
		return 0
	}
	if d.Percent < 100 && d.Policy != "none" {
		score -= 10
	}
	return score
}

func letter(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

// GradeAtLeast reports whether grade is the same as or better than min.
func GradeAtLeast(grade, min string) bool {
	order := "ABCDF"
	g, m := strings.Index(order, grade), strings.Index(order, strings.ToUpper(min))
	return g >= 0 && m >= 0 && g <= m
}

// ValidGrade reports whether g is one of A, B, C, D or F.
func ValidGrade(g string) bool {
	return len(g) == 1 && strings.Contains("ABCDF", strings.ToUpper(g))
}
