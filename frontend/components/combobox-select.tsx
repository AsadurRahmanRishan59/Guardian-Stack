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
import { ChevronsUpDown, Check, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { useState } from "react";

interface ComboboxSelectProps<T extends object> {
  items: T[];
  value?: number;
  onChange: (value: number | undefined) => void;
  placeholder?: string;
  displayField: keyof T;
  valueField: keyof T;
  loading?: boolean;
  error?: string;
  disabled?: boolean;
  // Generic render functions
  renderItem?: (item: T) => React.ReactNode;
  renderSelected?: (item: T) => React.ReactNode;
}

export function ComboboxSelect<T extends object>({
  items,
  value,
  onChange,
  placeholder = "Select...",
  displayField,
  valueField,
  loading,
  error,
  disabled = false,
  renderItem,
  renderSelected,
}: ComboboxSelectProps<T>) {
  const [open, setOpen] = useState(false);

  const selectedItem = items.find((item) => item[valueField] === value);

  const getItemDisplay = (item: T) => {
    return renderItem ? renderItem(item) : String(item[displayField]);
  };

  const getSelectedDisplay = () => {
    if (!selectedItem) {
      return <span className="text-muted-foreground">{placeholder}</span>;
    }

    return renderSelected
      ? renderSelected(selectedItem)
      : String(selectedItem[displayField]);
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
                "w-full justify-between",
                disabled && "cursor-not-allowed opacity-50"
              )}
            >
              {getSelectedDisplay()}
              <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
            </Button>
          </PopoverTrigger>
          <PopoverContent
            className="p-0"
            style={{ width: "var(--radix-popover-trigger-width)" }}
          >
            <Command>
              <CommandInput
                placeholder={`${placeholder.toLowerCase()}...`}
                disabled={disabled}
              />
              <CommandList>
                <CommandEmpty>No item found.</CommandEmpty>
                <CommandGroup>
                  {items.map((item) => {
                    const itemValue = item[valueField];
                    const isSelected = itemValue === value;
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
                        onSelect={() => {
                          if (!disabled) {
                            onChange(
                              isSelected ? undefined : (itemValue as number)
                            );
                            setOpen(false);
                          }
                        }}
                      >
                        <Check
                          className={cn(
                            "mr-2 h-4 w-4 shrink-0",
                            isSelected ? "opacity-100" : "opacity-0"
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
