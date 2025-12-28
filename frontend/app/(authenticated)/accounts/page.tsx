"use client";

import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { motion } from "framer-motion";
import { UploadCloud, FileText } from "lucide-react";
import { useCurrentUser } from "@/features/auth/auth.react.query";
import { AppRole } from "@/types/auth.types";

export default function AccountsPage() {
  const { data: user, isLoading } = useCurrentUser();

  if (isLoading) return <p className="text-foreground">Loading...</p>;

  // All account-related features
  const accountModules = [
    {
      title: "Voucher Upload",
      icon: UploadCloud,
      href: "/accounts/upload",
      description:
        "Upload daily vouchers (BP, JV, FT, BR, JV/A) with validation and auto-cleanup.",
      roles: [
        AppRole.ADMIN,
        AppRole.ACCOUNT_MANAGER,
        AppRole.ACCOUNT_USER,
        AppRole.ACCOUNT_USER,
      ],
    },
    {
      title: "Voucher List",
      icon: FileText,
      href: "/accounts/list",
      description:
        "View, filter, search and download vouchers with pagination.",
      roles: [AppRole.ADMIN, AppRole.ACCOUNT_MANAGER, AppRole.ACCOUNT_USER],
    },
  ];

  // Filter based on user role
  const visibleModules = accountModules.filter((mod) =>
    mod.roles.some((role) => user?.roles?.includes(role))
  );

  return (
    <div className="min-h-screen flex flex-col items-center justify-start bg-background dark:bg-background p-4">
      <h1 className="text-2xl font-bold text-foreground dark:text-foreground mb-8 drop-shadow-lg">
        Accounts Module
      </h1>

      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-6 max-w-6xl w-full">
        {visibleModules.map((mod, index) => {
          const Icon = mod.icon;
          return (
            <motion.div
              key={mod.title}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1, duration: 0.5 }}
            >
              <Link href={mod.href}>
                <Card className="backdrop-blur-xl border border-border bg-card dark:bg-card shadow-lg hover:bg-card/20 dark:hover:bg-card/30 transition-all duration-300 cursor-pointer rounded-xl p-4">
                  <CardHeader>
                    <CardTitle className="text-md flex items-center gap-2">
                      <Icon className="w-6 h-6" />
                      {mod.title}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-card-foreground/80 text-sm">
                      {mod.description}
                    </p>
                  </CardContent>
                </Card>
              </Link>
            </motion.div>
          );
        })}
      </div>
    </div>
  );
}
