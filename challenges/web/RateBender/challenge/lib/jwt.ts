import { SignJWT, jwtVerify } from "jose"

const JWT_SECRET = new TextEncoder().encode(
  process.env.JWT_SECRET || "default_insecure_secret_do_not_use_in_production",
)

export async function signJwt(payload: any): Promise<string> {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(JWT_SECRET)
}

export async function verifyJwt(token: string): Promise<any> {
  try {
    const { payload } = await jwtVerify(token, JWT_SECRET)
    return payload
  } catch (error) {
    return null
  }
}

// Intentional vulnerability: JWT verification doesn't check the algorithm
export async function verifyJwtVulnerable(token: string): Promise<any> {
  try {
    // This function doesn't validate the algorithm, allowing for algorithm confusion attacks
    const parts = token.split(".")
    if (parts.length !== 3) return null

    // Decode the payload without verifying the signature
    const payload = JSON.parse(Buffer.from(parts[1], "base64").toString())

    // Only check if the token is expired
    const now = Math.floor(Date.now() / 1000)
    if (payload.exp && payload.exp < now) return null

    return payload
  } catch (error) {
    return null
  }
}
