"use client"

import { useState, useEffect } from "react"
import { useRouter } from "next/navigation"
import { useToast } from "@/components/ui/use-toast"

export default function Dashboard() {
  const [loading, setLoading] = useState(true)
  const [userData, setUserData] = useState<any>(null)
  const [accessLevel, setAccessLevel] = useState(0)
  const router = useRouter()
  const { toast } = useToast()

  useEffect(() => {
    async function checkAuth() {
      try {
        const response = await fetch("/api/auth/verify")

        if (!response.ok) {
          throw new Error("Authentication failed")
        }

        const data = await response.json()
        setUserData(data.user)
        setAccessLevel(data.accessLevel || 0)
        setLoading(false)
      } catch (error) {
        toast({
          variant: "destructive",
          title: "Authentication Error",
          description: "Please login to access this page",
        })
        router.push("/login")
      }
    }

    checkAuth()
  }, [router, toast])

  const handleAccessFlag = async () => {
    try {
      const response = await fetch("/api/flag/access")

      if (!response.ok) {
        const data = await response.json()
        toast({
          variant: "destructive",
          title: "Access Denied",
          description: data.message || "You don't have permission to access the flag",
        })
        return
      }

      router.push("/flag")
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Error",
        description: "Failed to access the flag",
      })
    }
  }

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-900 text-white">
        <div className="text-xl">Loading...</div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-3xl font-bold mb-6">User Dashboard</h1>

        <div className="bg-gray-800 p-6 rounded-lg mb-8">
          <h2 className="text-xl font-semibold mb-4">User Information</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <p className="text-gray-400">Username:</p>
              <p className="font-medium">{userData?.username || "Unknown"}</p>
            </div>
            <div>
              <p className="text-gray-400">Role:</p>
              <p className="font-medium">{userData?.role || "Standard User"}</p>
            </div>
            <div>
              <p className="text-gray-400">Access Level:</p>
              <p className="font-medium">{accessLevel}</p>
            </div>
            <div>
              <p className="text-gray-400">Last Login:</p>
              <p className="font-medium">{new Date().toLocaleString()}</p>
            </div>
          </div>
        </div>

        <div className="bg-gray-800 p-6 rounded-lg">
          <h2 className="text-xl font-semibold mb-4">Actions</h2>
          <div className="flex flex-wrap gap-4">
            <button
              onClick={handleAccessFlag}
              className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
            >
              Access Flag (Requires Admin)
            </button>
            <button
              onClick={() => router.push("/profile")}
              className="bg-gray-600 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded"
            >
              Edit Profile
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
