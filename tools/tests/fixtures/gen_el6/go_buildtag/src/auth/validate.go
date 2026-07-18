//go:build !prod

package auth

// validateAdmin enforces the admin invariant. Only compiled in non-prod builds.
func validateAdmin(caller string) error {
    if caller != "admin" {
        return fmt.Errorf("permission denied")
    }
    return nil
}
