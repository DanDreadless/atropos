package parsers

import (
	_ "embed"
	"regexp"
	"strings"
	"sync"
)

// Jump lists are named by a hash of the application that wrote them. This
// table names the application for the hashes that are known. It is Eric
// Zimmerman's list from his JumpList library (MIT licence; see
// THIRD_PARTY_NOTICES.md), embedded unchanged.
//
//go:embed jumplist_appids.txt
var appIDList string

var (
	appIDOnce  sync.Once
	appIDNames map[string]string
	reAppID    = regexp.MustCompile(`^"([0-9A-Fa-f]{12,16})"\|"(.*)"$`)
)

// appName returns the application a jump list's ID belongs to, or "".
func appName(id string) string {
	appIDOnce.Do(func() {
		appIDNames = map[string]string{}
		for _, line := range strings.Split(appIDList, "\n") {
			m := reAppID.FindStringSubmatch(strings.TrimSpace(strings.TrimPrefix(line, "\uFEFF")))
			if m == nil {
				continue
			}
			// Some IDs in the list have lost their leading zeros.
			k := strings.ToLower(strings.Repeat("0", 16-len(m[1])) + m[1])
			if have, ok := appIDNames[k]; ok && have != m[2] {
				appIDNames[k] = have + " / " + m[2]
				continue
			}
			appIDNames[k] = m[2]
		}
	})
	id = strings.ToLower(strings.TrimSpace(id))
	if len(id) > 16 || len(id) < 12 {
		return ""
	}
	return appIDNames[strings.Repeat("0", 16-len(id))+id]
}
