"use client"

import { useState, useEffect } from "react"
import { useRouter } from "next/navigation"
import { useToast } from "@/components/ui/use-toast"

export default function FlagPage() {
  const [loading, setLoading] = useState(true)
  const [flag, setFlag] = useState("")
  const [error, setError] = useState("")
  const router = useRouter()
  const { toast } = useToast()

  useEffect(() => {
    async function fetchFlag() {
      try {
        // This endpoint requires admin privileges and proper authorization
        const response = await fetch("/api/flag/get")

        if (!response.ok) {
          const data = await response.json()
          setError(data.message || "Access denied")
          setLoading(false)
          return
        }

        const data = await response.json()
        setFlag(data.flag)
        setLoading(false)
      } catch (error) {
        setError("Failed to fetch flag")
        setLoading(false)
      }
    }

    fetchFlag()
  }, [router, toast])

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-900 text-white">
        <div className="text-xl">Loading...</div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center p-24 bg-gray-900 text-white">
        <div className="max-w-2xl w-full text-center">
          <h1 className="text-4xl font-bold mb-6">Access Denied</h1>
          <div className="bg-red-900/30 border-2 border-red-500 p-8 rounded-lg mb-8">
            <p className="text-xl mb-4">{error}</p>
            <p>You don't have the required permissions to view the flag.</p>
          </div>
          <button
            onClick={() => router.push("/dashboard")}
            className="bg-gray-600 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded"
          >
            Return to Dashboard
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="flex min-h-screen flex-col items-center justify-center p-24 bg-gray-900 text-white">
      <div className="max-w-2xl w-full text-center">
        <h1 className="text-4xl font-bold mb-6">Congratulations!</h1>
        <div className="bg-green-900/30 border-2 border-green-500 p-8 rounded-lg mb-8">
          <p className="text-2xl font-mono mb-4">FLAG: {flag}</p>
          <p>You successfully bypassed all security layers!</p>
        </div>
        <button
          onClick={() => router.push("/dashboard")}
          className="bg-gray-600 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded"
        >
          Return to Dashboard
        </button>
      </div>
    </div>
  )
}
