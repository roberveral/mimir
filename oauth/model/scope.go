package model

// ScopeSet implements a set functionality for the given scopes
// for efficient lookup for concrete scopes.
type ScopeSet map[string]struct{}

// NewScopeSet creates a ScopeSet which contains all the scopes in
// the given slice.
func NewScopeSet(scopes []string) ScopeSet {
	set := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		set[scope] = struct{}{}
	}
	return set
}

// Contains checks if the given scope is in the scope set.
func (s ScopeSet) Contains(scope string) bool {
	_, ok := s[scope]
	return ok
}
