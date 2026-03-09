// components/table/FilterToggle.tsx
import React from 'react';
import { SlidersHorizontal } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

interface FilterToggleProps {
  isOpen: boolean;
  onToggle: () => void;
  activeFiltersCount: number;
  isLoading?: boolean;
}

export const FilterToggle: React.FC<FilterToggleProps> = ({
  isOpen,
  onToggle,
  activeFiltersCount,
  isLoading = false,
}) => {
  return (
    <Button
      variant="outline"
      onClick={onToggle}
      disabled={isLoading}
      className={cn(
        'relative h-9 gap-2 border-gs-line text-t2 hover:text-t1 hover:bg-surface-2 hover:border-gs-line-2 transition-colors',
        isOpen && 'bg-brand-soft border-brand-border text-brand',
      )}
    >
      <SlidersHorizontal className="h-4 w-4" />
      <span className="hidden sm:inline">Filters</span>
      {activeFiltersCount > 0 && (
        <span className="flex items-center justify-center h-4 w-4 rounded-full bg-brand text-white text-[10px] font-semibold leading-none">
          {activeFiltersCount}
        </span>
      )}
    </Button>
  );
};