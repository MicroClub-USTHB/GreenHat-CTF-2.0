import { NextResponse } from "next/server"
import { generateCsrfToken } from "@/lib/csrf"

export async function GET() {
  const csrfToken = generateCsrfToken()

  return NextResponse.json({ csrfToken })
}
