import { NextResponse } from "next/server"
import { cookies } from "next/headers"
import { verifyJwtVulnerable } from "@/lib/jwt"

// The real flag
const FLAG = "ghctf{N3XT_JWT_ALG0_CONF5ION_CSRF_BYPA55_2023}"

export async function GET(request: Request) {
  try {
    const cookieStore = cookies()
    const token = cookieStore.get("auth_token")?.value

    if (!token) {
      return NextResponse.json({ message: "Authentication required" }, { status: 401 })
    }

    // Verify JWT (vulnerable implementation)
    const payload = await verifyJwtVulnerable(token)

    if (!payload) {
      return NextResponse.json({ message: "Invalid or expired token" }, { status: 401 })
    }

    // Check if user has admin role
    if (payload.role !== "admin") {
      return NextResponse.json({ message: "Admin privileges required" }, { status: 403 })
    }

    // Check if user has sufficient access level
    if ((payload.accessLevel || 0) < 10) {
      return NextResponse.json({ message: "Insufficient access level" }, { status: 403 })
    }

    // Return the flag
    return NextResponse.json({ flag: FLAG })
  } catch (error) {
    return NextResponse.json({ message: "Failed to retrieve flag" }, { status: 500 })
  }
}
