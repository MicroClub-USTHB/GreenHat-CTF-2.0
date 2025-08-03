import Link from "next/link"

export default function Home() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-24 bg-gray-900 text-white">
      <div className="max-w-2xl w-full text-center">
        <h1 className="text-4xl font-bold mb-6">RateBender</h1>
        <p className="text-xl mb-8">Welcome to the Multi-Layer Security Bypass Challenge!</p>
        <div className="bg-gray-800 p-6 rounded-lg mb-8">
          <h2 className="text-2xl font-semibold mb-4">Mission</h2>
          <p className="mb-4">Your goal is to bypass multiple security layers and access the protected flag.</p>
          <p>Good luck, elite hacker!</p>
        </div>
        <div className="flex justify-center gap-4">
          <Link href="/login" className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">
            Login
          </Link>
          <Link href="/dashboard" className="bg-gray-600 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded">
            Dashboard (Protected)
          </Link>
        </div>
      </div>
    </main>
  )
}
