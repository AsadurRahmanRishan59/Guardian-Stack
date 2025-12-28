// Example usage in a component
// components/VoucherActions.tsx

'use client';

import { useCurrentUser } from '@/lib/hooks/useAuth';
import { canDeleteVoucher, canCreateVoucher } from '@/lib/utils/permission-utils';

interface VoucherActionsProps {
  voucherId: number;
  onDelete: (id: number) => void;
}

export function VoucherActions({ voucherId, onDelete }: VoucherActionsProps) {
  const { data: user } = useCurrentUser();

  if (!user) return null;

  return (
    <div className="flex gap-2">
      <button className="text-blue-600 hover:text-blue-800">
        View
      </button>
      
      {canCreateVoucher(user.roles) && (
        <button className="text-green-600 hover:text-green-800">
          Edit
        </button>
      )}
      
      {canDeleteVoucher(user.roles) && (
        <button 
          onClick={() => onDelete(voucherId)}
          className="text-red-600 hover:text-red-800"
        >
          Delete
        </button>
      )}
    </div>
  );
}