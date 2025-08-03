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

    return NextResponse.json({
      user: {
        id: payload.sub,
        username: payload.username,
        role: payload.role,
      },
      accessLevel: payload.accessLevel || 0,
    })
  } catch (error) {
    return NextResponse.json({ message: "Authentication failed" }, { status: 401 })
  }
}
