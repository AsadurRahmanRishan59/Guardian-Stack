import { AdminUserViewContainer } from "@/features/masteradmin/user/components/AdminUserViewContainer";

export default function AdminUserPage() {
  return <AdminUserViewContainer />
}

// 'use client'
// import Link from "next/link";
// import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
// import { motion } from "framer-motion";
// import { Settings, List } from "lucide-react";

// export default function AdminUserPage() {
//   const modules = [
//     {
//       title: "Setup",
//       icon: Settings,
//       href: "/admin/user/setup",
//       description: "Configure user roles and permissions.",
//     },
//     {
//       title: "List",
//       icon: List,
//       href: "/admin/user/list",
//       description: "View and manage all existing users.",
//     },
//   ];

//   return (
//     <div className="min-h-screen flex flex-col items-center justify-start bg-background dark:bg-background p-4">
//       <h1 className="text-2xl font-bold text-foreground dark:text-foreground mb-8 drop-shadow-lg">User Management</h1>
//       <div className="grid grid-cols-1 sm:grid-cols-3 gap-6 max-w-7xl w-full">
//         {modules.map((mod, index) => {
//           const Icon = mod.icon;
//           return (
//             <motion.div
//               key={mod.title}
//               initial={{ opacity: 0, y: 20 }}
//               animate={{ opacity: 1, y: 0 }}
//               transition={{ delay: index * 0.1, duration: 0.5 }}
//             >
//               <Link href={mod.href} aria-label={`Open ${mod.title} module`}>
//                 <Card className="backdrop-blur-xl border border-border bg-card dark:bg-card dark:border-border shadow-lg hover:bg-card/20 dark:hover:bg-card/30 transition-all duration-300 cursor-pointer rounded-xl p-4">
//                   <CardHeader>
//                     <CardTitle className="text-md flex items-center gap-2 text-card-foreground dark:text-card-foreground drop-shadow-md">
//                       <Icon className="w-5 h-5" />
//                       <span>{mod.title}</span>
//                     </CardTitle>
//                   </CardHeader>
//                   <CardContent>
//                     <p className="text-card-foreground/80 dark:text-card-foreground/80 text-sm">{mod.description}</p>
//                   </CardContent>
//                 </Card>
//               </Link>
//             </motion.div>
//           );
//         })}
//       </div>
//     </div>
//   );
// }
