import { NextResponse } from "next/server"

// The vulnerable route that doesn't properly check authentication
export async function GET(request: Request) {
  // This route handler is intentionally vulnerable - it doesn't check for authentication
  // In a real app, this would verify the auth_token cookie

  return NextResponse.json({
    flag: "ghctf{BYpa$s3d_your_L09!C_LiKE_a_n1nj@}",
  })
}
