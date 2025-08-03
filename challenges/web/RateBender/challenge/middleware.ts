import { NextResponse } from "next/server"
import type { NextRequest } from "next/server"
import { verifyJwtVulnerable } from "@/lib/jwt"

export async function middleware(request: NextRequest) {
  const path = request.nextUrl.pathname

  // Public routes that don't require authentication
  if (path === "/" || path === "/login" || path.startsWith("/api/auth/login") || path.startsWith("/api/csrf")) {
    return NextResponse.next()
  }

  // Check for authentication token
  const token = request.cookies.get("auth_token")?.value

  if (!token) {
    // Redirect to login if no token is present
    return NextResponse.redirect(new URL("/login", request.url))
  }

  // Verify JWT (vulnerable implementation)
  const payload = await verifyJwtVulnerable(token)

  if (!payload) {
    // Redirect to login if token is invalid
    return NextResponse.redirect(new URL("/login", request.url))
  }

  // Special protection for flag routes
  if (path === "/flag" || path.startsWith("/api/flag")) {
    // Check if user has admin role
    if (payload.role !== "admin") {
      // Intentional vulnerability: Path traversal in the middleware
      // The middleware only checks exact paths, not normalized paths
      // This allows bypassing by using different path formats
      if (path === "/flag" || path === "/api/flag/access" || path === "/api/flag/get") {
        return NextResponse.redirect(new URL("/login", request.url))
      }
    }
  }

  return NextResponse.next()
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
}
