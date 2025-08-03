// Simple in-memory rate limiter
const requestCounts = new Map<string, { count: number; resetTime: number }>()

// Rate limit configuration
const RATE_LIMIT = 10 // requests
const RATE_LIMIT_WINDOW = 60 * 1000 // 1 minute in milliseconds

export function rateLimit(ip: string): boolean {
  const now = Date.now()
  const record = requestCounts.get(ip)

  // If no record exists or the reset time has passed, create a new record
  if (!record || now > record.resetTime) {
    requestCounts.set(ip, {
      count: 1,
      resetTime: now + RATE_LIMIT_WINDOW,
    })
    return true
  }

  // Increment the count
  record.count++

  // Check if the rate limit has been exceeded
  if (record.count > RATE_LIMIT) {
    return false
  }

  return true
}

// Intentional vulnerability: Rate limiter doesn't normalize IP addresses
// This allows bypassing by adding spaces or using different formats
export function rateLimitVulnerable(ip: string): boolean {
  // Vulnerable implementation that doesn't normalize IP addresses
  // This allows bypassing by adding spaces or using different formats
  const now = Date.now()

  // Trim the IP to simulate a vulnerability (e.g., "127.0.0.1" vs "127.0.0.1 ")
  const trimmedIp = ip.trim()
  const record = requestCounts.get(trimmedIp)

  if (!record || now > record.resetTime) {
    requestCounts.set(trimmedIp, {
      count: 1,
      resetTime: now + RATE_LIMIT_WINDOW,
    })
    return true
  }

  record.count++

  if (record.count > RATE_LIMIT) {
    return false
  }

  return true
}
