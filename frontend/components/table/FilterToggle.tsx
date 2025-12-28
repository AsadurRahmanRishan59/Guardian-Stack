// 4. Filter Toggle Component
// components/table/FilterToggle.tsx
import React from 'react';
import { Filter } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

interface FilterToggleProps {
  isOpen: boolean;
  onToggle: () => void;
  activeFiltersCount: number;
  isLoading?: boolean;
}

export const FilterToggle: React.FC<FilterToggleProps> = ({
  onToggle,
  activeFiltersCount,
  isLoading = false,
}) => {
  return (
    <Button
      variant="outline"
      onClick={onToggle}
      className="relative"
      disabled={isLoading}
    >
      <Filter className="w-4 h-4 mr-2" />
      Filters
      {activeFiltersCount > 0 && (
        <Badge className="ml-2 h-5 w-5 rounded-full p-0 flex items-center justify-center text-xs">
          {activeFiltersCount}
        </Badge>
      )}
    </Button>
  );
};
