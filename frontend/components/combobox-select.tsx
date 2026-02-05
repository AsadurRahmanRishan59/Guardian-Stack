"use client";

import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ChevronsUpDown, Check, Loader2, X } from "lucide-react";
import { cn } from "@/lib/utils";
import { useState } from "react";

// Single select props
interface ComboboxSelectSingleProps<T extends object> {
  items: T[];
  value?: number;
  onChange: (value: number | undefined) => void;
  placeholder?: string;
  displayField: keyof T;
  valueField: keyof T;
  loading?: boolean;
  error?: string;
  disabled?: boolean;
  multiple?: false;
  // Generic render functions
  renderItem?: (item: T) => React.ReactNode;
  renderSelected?: (item: T) => React.ReactNode;
}

// Multi select props
interface ComboboxSelectMultipleProps<T extends object> {
  items: T[];
  value?: number[];
  onChange: (value: number[] | undefined) => void;
  placeholder?: string;
  displayField: keyof T;
  valueField: keyof T;
  loading?: boolean;
  error?: string;
  disabled?: boolean;
  multiple: true;
  // Generic render functions
  renderItem?: (item: T) => React.ReactNode;
  renderSelected?: (item: T) => React.ReactNode;
}

type ComboboxSelectProps<T extends object> =
  | ComboboxSelectSingleProps<T>
  | ComboboxSelectMultipleProps<T>;

export function ComboboxSelect<T extends object>(
  props: ComboboxSelectProps<T>
) {
  const {
    items,
    value,
    onChange,
    placeholder = "Select...",
    displayField,
    valueField,
    loading,
    error,
    disabled = false,
    multiple = false,
    renderItem,
    renderSelected,
  } = props;

  const [open, setOpen] = useState(false);

  // Normalize value to array for easier handling
  const selectedValues = multiple
    ? Array.isArray(value)
      ? value
      : []
    : Array.isArray(value)
    ? []
    : value !== undefined
    ? [value]
    : [];

  const selectedItems = items.filter((item) =>
    selectedValues.includes(item[valueField] as number)
  );

  const getItemDisplay = (item: T) => {
    return renderItem ? renderItem(item) : String(item[displayField]);
  };

  const getSelectedDisplay = () => {
    if (selectedItems.length === 0) {
      return <span className="text-muted-foreground">{placeholder}</span>;
    }

    if (multiple) {
      return (
        <div className="flex flex-wrap gap-1">
          {selectedItems.map((item) => (
            <Badge
              key={String(item[valueField])}
              variant="secondary"
              className="mr-1"
            >
              {renderSelected
                ? renderSelected(item)
                : String(item[displayField])}
              <span
                role="button"
                tabIndex={0}
                className="ml-1 rounded-full outline-none ring-offset-background focus:ring-2 focus:ring-ring focus:ring-offset-2 cursor-pointer inline-flex"
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    e.stopPropagation();
                    handleToggle(item[valueField] as number);
                  }
                }}
                onMouseDown={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                }}
                onClick={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  handleToggle(item[valueField] as number);
                }}
              >
                <X className="h-3 w-3 text-muted-foreground hover:text-foreground" />
              </span>
            </Badge>
          ))}
        </div>
      );
    }

    const selectedItem = selectedItems[0];
    return renderSelected
      ? renderSelected(selectedItem)
      : String(selectedItem[displayField]);
  };

  const handleToggle = (itemValue: number) => {
    if (disabled) return;

    if (multiple) {
      const currentValues = Array.isArray(value) ? value : [];
      const newValues = currentValues.includes(itemValue)
        ? currentValues.filter((v) => v !== itemValue)
        : [...currentValues, itemValue];

      // Type assertion needed due to discriminated union
      (onChange as (value: number[] | undefined) => void)(
        newValues.length > 0 ? newValues : undefined
      );
    } else {
      // Type assertion needed due to discriminated union
      (onChange as (value: number | undefined) => void)(
        value === itemValue ? undefined : itemValue
      );
      setOpen(false);
    }
  };

  const isSelected = (itemValue: number) => {
    return selectedValues.includes(itemValue);
  };

  return (
    <>
      {loading ? (
        <div className="flex items-center space-x-2 p-3 border rounded-md bg-muted/50 backdrop-blur-sm">
          <Loader2 className="h-4 w-4 animate-spin" />
          <span className="text-sm text-muted-foreground">Loading...</span>
        </div>
      ) : error ? (
        <div className="p-3 border rounded-md bg-destructive/10 text-destructive text-sm">
          {error}
        </div>
      ) : (
        <Popover open={open && !disabled} onOpenChange={setOpen}>
          <PopoverTrigger asChild>
            <Button
              variant="outline"
              role="combobox"
              aria-expanded={open}
              disabled={disabled}
              className={cn(
                "w-full justify-between min-h-8 h-auto",
                disabled && "cursor-not-allowed opacity-50"
              )}
            >
              <div className="flex-1 text-left overflow-hidden">
                {getSelectedDisplay()}
              </div>
              <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
            </Button>
          </PopoverTrigger>
          <PopoverContent
            className="p-0"
            style={{ width: "var(--radix-popover-trigger-width)" }}
          >
            <Command>
              <CommandInput
                placeholder={`Search ${placeholder.toLowerCase()}...`}
                disabled={disabled}
              />
              <CommandList>
                <CommandEmpty>No item found.</CommandEmpty>
                <CommandGroup>
                  {items.map((item) => {
                    const itemValue = item[valueField] as number;
                    const selected = isSelected(itemValue);
                    // Create a unique value by combining the display field with the unique valueField
                    const uniqueValue = `${String(item[displayField])}-${String(
                      itemValue
                    )}`;

                    return (
                      <CommandItem
                        key={String(itemValue)}
                        value={uniqueValue}
                        disabled={disabled}
                        className={cn("cursor-pointer", renderItem && "py-3")}
                        onSelect={() => handleToggle(itemValue)}
                      >
                        <Check
                          className={cn(
                            "mr-2 h-4 w-4 shrink-0",
                            selected ? "opacity-100" : "opacity-0"
                          )}
                        />
                        {getItemDisplay(item)}
                      </CommandItem>
                    );
                  })}
                </CommandGroup>
              </CommandList>
            </Command>
          </PopoverContent>
        </Popover>
      )}
    </>
  );
}