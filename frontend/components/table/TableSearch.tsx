// 2. Table Search Component
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
      <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
      <Input
        placeholder={placeholder}
        className="pl-10"
        onChange={(e) => onChange(e.target.value)}
        value={value}
      />
    </div>
  );
};