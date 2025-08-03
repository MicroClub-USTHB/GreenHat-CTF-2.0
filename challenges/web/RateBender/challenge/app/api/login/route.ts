import { cookies } from "next/headers"
import { NextResponse } from "next/server"

// In a real app, this would be in a database
const ADMIN_USERNAME = "admin"
const ADMIN_PASSWORD = "supersecretpassword123"

export async function POST(request: Request) {
  try {
    const body = await request.json()
    const { username, password } = body

    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
      // Set authentication cookie
      cookies().set("auth_token", "authenticated", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge: 60 * 60, // 1 hour
        path: "/",
      })

      return NextResponse.json({ success: true })
    }

    return NextResponse.json({ message: "Invalid username or password" }, { status: 401 })
  } catch (error) {
    return NextResponse.json({ message: "An error occurred" }, { status: 500 })
  }
}
  