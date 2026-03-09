// components/table/TableSearch.tsx
import React from 'react';
import { Search } from 'lucide-react';
import { Input } from '@/components/ui/input';

interface TableSearchProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  className?: string;
}

export const TableSearch: React.FC<TableSearchProps> = ({
  value,
  onChange,
  placeholder = 'Search...',
  className = '',
}) => {
  return (
    <div className={`flex-1 relative ${className}`}>
      <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-t3 pointer-events-none" />
      <Input
        placeholder={placeholder}
        className="pl-9 h-9 bg-surface border-gs-line text-t1 placeholder:text-t4 focus-visible:ring-brand focus-visible:border-brand transition-colors"
        onChange={(e) => onChange(e.target.value)}
        value={value}
      />
    </div>
  );
};