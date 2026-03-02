// features/masteradmin/audit/user/user.types.ts

import { SignUpMethod } from "../../user/user.types";

export interface MasterAdminUserAuditDTO {
  revisionNumber: number;
  revisionType: string;
  timestamp: string;
  changedBy: string;
  ipAddress: string;
  userId: number;
  username: string;
  email: string;
  signUpMethod: SignUpMethod;
  roles: string[];
  enabled: boolean;
  accountLocked: boolean;
  accountExpiryDate: string;
  credentialsExpiryDate: string;
  lastPasswordChange: string;
}

export interface AuditFilterRequest {
  userId:number;
  email:string;
  changedBy:string;
  ipAddress:string;
  revisionTypes:string;
  from:string;
  to:string;
  page:string;
  size:string;
}

