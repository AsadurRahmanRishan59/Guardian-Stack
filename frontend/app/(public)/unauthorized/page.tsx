// app/unauthorized/page.tsx
"use client";

import Link from "next/link";
import { ShieldOff } from "lucide-react";

export default function UnauthorizedPage() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 p-4">
      <div className="bg-white dark:bg-gray-800 p-10 rounded-2xl shadow-lg max-w-lg w-full text-center transition-colors">
        {/* Icon */}
        <div className="flex items-center justify-center w-24 h-24 mx-auto rounded-full bg-red-100 dark:bg-red-900 mb-6">
          <ShieldOff className="w-12 h-12 text-red-600 dark:text-red-400" />
        </div>

        {/* Title */}
        <h1 className="text-3xl font-extrabold text-gray-900 dark:text-gray-100 mb-4">
          Access Denied
        </h1>

        {/* Description */}
        <p className="text-gray-600 dark:text-gray-300 mb-6">
          You don’t have permission to view this page. Please contact your administrator
          if you think this is an error.
        </p>

        {/* Dashboard Button */}
        <Link
          href="/dashboard"
          className="inline-flex items-center justify-center px-6 py-3 text-white bg-blue-600 dark:bg-blue-500 hover:bg-blue-700 dark:hover:bg-blue-600 rounded-lg font-medium shadow-md transition-colors duration-200"
        >
          Go to Dashboard
        </Link>
      </div>
    </div>
  );
}
