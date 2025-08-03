import crypto from "crypto"

// Store CSRF tokens with their expiration time
const csrfTokens = new Map<string, number>()

// Generate a new CSRF token
export function generateCsrfToken(): string {
  const token = crypto.randomBytes(32).toString("hex")
  // Token expires in 10 minutes
  csrfTokens.set(token, Date.now() + 10 * 60 * 1000)
  return token
}

// Validate a CSRF token
export function validateCsrfToken(token: string): boolean {
  if (!token) return false

  const expiry = csrfTokens.get(token)
  if (!expiry) return false

  // Check if token has expired
  if (Date.now() > expiry) {
    csrfTokens.delete(token)
    return false
  }

  return true
}

// Intentional vulnerability: CSRF token validation has a timing attack vulnerability
export function validateCsrfTokenVulnerable(token: string): boolean {
  if (!token) return false

  // Vulnerable implementation that doesn't use constant-time comparison
  // This allows for timing attacks
  for (const [storedToken, expiry] of csrfTokens.entries()) {
    if (Date.now() > expiry) {
      csrfTokens.delete(storedToken)
      continue
    }

    if (token === storedToken) {
      return true
    }
  }

  return false
}
