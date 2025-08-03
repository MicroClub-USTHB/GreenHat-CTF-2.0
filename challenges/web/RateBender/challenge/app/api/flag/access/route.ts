import { NextResponse } from "next/server"
import { cookies } from "next/headers"
import { verifyJwtVulnerable } from "@/lib/jwt"

export async function GET() {
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

    return NextResponse.json({ success: true })
  } catch (error) {
    return NextResponse.json({ message: "Access check failed" }, { status: 500 })
  }
}
