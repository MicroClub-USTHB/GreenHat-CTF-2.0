import { NextResponse } from "next/server"
import { cookies } from "next/headers"
import { signJwt } from "@/lib/jwt"
import { validateCsrfTokenVulnerable } from "@/lib/csrf"
import { rateLimitVulnerable } from "@/lib/rate-limit"

// In a real app, this would be in a database
const USERS = [
  { id: 1, username: "user", password: "password123", role: "user", accessLevel: 1 },
  { id: 2, username: "admin", password: "super_secure_admin_password_123!", role: "admin", accessLevel: 10 },
]

export async function POST(request: Request) {
  try {
    // Get client IP for rate limiting
    const ip = request.headers.get("x-forwarded-for") || "127.0.0.1"

    // Check rate limit (vulnerable implementation)
    if (!rateLimitVulnerable(ip)) {
      return NextResponse.json({ message: "Too many requests. Please try again later." }, { status: 429 })
    }

    // Validate CSRF token (vulnerable implementation)
    const csrfToken = request.headers.get("x-csrf-token")
    if (!validateCsrfTokenVulnerable(csrfToken || "")) {
      return NextResponse.json({ message: "Invalid or expired CSRF token" }, { status: 403 })
    }

    const body = await request.json()
    const { username, password } = body

    // Find user
    const user = USERS.find((u) => u.username === username && u.password === password)

    if (!user) {
      return NextResponse.json({ message: "Invalid username or password" }, { status: 401 })
    }

    // Create JWT token
    const token = await signJwt({
      sub: user.id,
      username: user.username,
      role: user.role,
      accessLevel: user.accessLevel,
    })

    // Set JWT as HTTP-only cookie
    cookies().set("auth_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 60 * 60, // 1 hour
      path: "/",
    })

    return NextResponse.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
      },
    })
  } catch (error) {
    return NextResponse.json({ message: "An error occurred during login" }, { status: 500 })
  }
}
