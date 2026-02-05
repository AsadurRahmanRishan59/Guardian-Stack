# ComboboxSelect Usage Examples

## Overview
The `ComboboxSelect` component supports both single and multi-select modes with full TypeScript type safety.

---

## Single Select Mode (Default)

### Basic Usage
```typescript
import { ComboboxSelect } from "@/components/combobox-select";

interface User {
  userId: number;
  username: string;
  email: string;
}

function UserSelector() {
  const [selectedUserId, setSelectedUserId] = useState<number>();
  const users: User[] = [...]; // Your data

  return (
    <ComboboxSelect
      items={users}
      value={selectedUserId}
      onChange={setSelectedUserId}
      placeholder="Select a user"
      displayField="username"
      valueField="userId"
    />
  );
}
```

### With Form (React Hook Form)
```typescript
<FormField
  control={form.control}
  name="userId"
  render={({ field }) => (
    <FormItem>
      <FormLabel>User</FormLabel>
      <FormControl>
        <ComboboxSelect
          items={users}
          value={field.value}
          onChange={field.onChange}
          placeholder="Select user"
          displayField="username"
          valueField="userId"
          // multiple is optional and defaults to false
        />
      </FormControl>
    </FormItem>
  )}
/>
```

### With Loading and Error States
```typescript
<ComboboxSelect
  items={users}
  value={selectedUserId}
  onChange={setSelectedUserId}
  placeholder="Select user"
  displayField="username"
  valueField="userId"
  loading={isLoading}
  error={error?.message}
  disabled={isDisabled}
/>
```

---

## Multi-Select Mode

### Basic Usage
```typescript
interface Role {
  roleId: number;
  roleName: string;
  description: string;
}

function RoleSelector() {
  const [selectedRoleIds, setSelectedRoleIds] = useState<number[]>();
  const roles: Role[] = [...]; // Your data

  return (
    <ComboboxSelect
      items={roles}
      value={selectedRoleIds}
      onChange={setSelectedRoleIds}
      placeholder="Select roles"
      displayField="roleName"
      valueField="roleId"
      multiple={true}  // Required for multi-select
    />
  );
}
```

### With Form (React Hook Form)
```typescript
<FormField
  control={form.control}
  name="roleIds"
  render={({ field }) => (
    <FormItem>
      <FormLabel>Roles</FormLabel>
      <FormControl>
        <ComboboxSelect
          items={roles}
          value={field.value}
          onChange={field.onChange}
          placeholder="Select roles"
          displayField="roleName"
          valueField="roleId"
          multiple={true}
        />
      </FormControl>
    </FormItem>
  )}
/>
```

---

## Advanced Usage

### Custom Rendering

#### Single Select with Custom Render
```typescript
<ComboboxSelect
  items={users}
  value={selectedUserId}
  onChange={setSelectedUserId}
  placeholder="Select user"
  displayField="username"
  valueField="userId"
  renderItem={(user) => (
    <div className="flex items-center gap-2">
      <Avatar className="h-6 w-6">
        <AvatarFallback>{user.username[0]}</AvatarFallback>
      </Avatar>
      <div>
        <div className="font-medium">{user.username}</div>
        <div className="text-xs text-muted-foreground">{user.email}</div>
      </div>
    </div>
  )}
  renderSelected={(user) => (
    <div className="flex items-center gap-2">
      <Avatar className="h-5 w-5">
        <AvatarFallback>{user.username[0]}</AvatarFallback>
      </Avatar>
      {user.username}
    </div>
  )}
/>
```

#### Multi-Select with Custom Render
```typescript
<ComboboxSelect
  items={roles}
  value={selectedRoleIds}
  onChange={setSelectedRoleIds}
  placeholder="Select roles"
  displayField="roleName"
  valueField="roleId"
  multiple={true}
  renderItem={(role) => (
    <div>
      <div className="font-medium">{role.roleName}</div>
      <div className="text-xs text-muted-foreground">{role.description}</div>
    </div>
  )}
  renderSelected={(role) => role.roleName}
/>
```

---

## Type Safety Examples

### ✅ Correct Usage

```typescript
// Single select - types match
const [userId, setUserId] = useState<number>();
<ComboboxSelect
  items={users}
  value={userId}              // number | undefined ✓
  onChange={setUserId}         // (number | undefined) => void ✓
  displayField="username"
  valueField="userId"
/>

// Multi select - types match
const [roleIds, setRoleIds] = useState<number[]>();
<ComboboxSelect
  items={roles}
  value={roleIds}              // number[] | undefined ✓
  onChange={setRoleIds}        // (number[] | undefined) => void ✓
  displayField="roleName"
  valueField="roleId"
  multiple={true}              // Required ✓
/>
```

### ❌ Incorrect Usage (TypeScript will error)

```typescript
// Error: value type mismatch
const [roleIds, setRoleIds] = useState<number[]>();
<ComboboxSelect
  items={roles}
  value={roleIds}              // number[] ❌
  onChange={setRoleIds}
  displayField="roleName"
  valueField="roleId"
  // missing multiple={true}  
/>

// Error: onChange type mismatch
const [userId, setUserId] = useState<number>();
<ComboboxSelect
  items={users}
  value={userId}
  onChange={setUserId}         // Expects (number | undefined) => void ❌
  displayField="username"
  valueField="userId"
  multiple={true}              // Should not be true for single select
/>
```

---

## Props Reference

### Common Props
| Prop | Type | Required | Description |
|------|------|----------|-------------|
| `items` | `T[]` | Yes | Array of items to display |
| `displayField` | `keyof T` | Yes | Key to use for display text |
| `valueField` | `keyof T` | Yes | Key to use as the value |
| `placeholder` | `string` | No | Placeholder text (default: "Select...") |
| `loading` | `boolean` | No | Show loading state |
| `error` | `string` | No | Error message to display |
| `disabled` | `boolean` | No | Disable the component |
| `renderItem` | `(item: T) => ReactNode` | No | Custom render for dropdown items |
| `renderSelected` | `(item: T) => ReactNode` | No | Custom render for selected item(s) |

### Single Select Props (`multiple?: false`)
| Prop | Type | Required | Description |
|------|------|----------|-------------|
| `value` | `number \| undefined` | No | Selected value |
| `onChange` | `(value: number \| undefined) => void` | Yes | Change handler |
| `multiple` | `false` | No | Single select mode (default) |

### Multi-Select Props (`multiple: true`)
| Prop | Type | Required | Description |
|------|------|----------|-------------|
| `value` | `number[] \| undefined` | No | Selected values array |
| `onChange` | `(value: number[] \| undefined) => void` | Yes | Change handler |
| `multiple` | `true` | Yes | Enable multi-select mode |

---

## Behavior Notes

### Single Select
- Clicking an item selects it and closes the popover
- Clicking the same item again deselects it (value becomes `undefined`)
- Display shows the selected item text

### Multi-Select
- Clicking items toggles selection without closing the popover
- Selected items appear as removable badges
- Click X on a badge to remove that item
- When all items are deselected, value becomes `undefined`
- Popover stays open for multiple selections

---

## Form Integration Pattern

### Zod Schema
```typescript
import { z } from "zod";

// Single select
const singleSelectSchema = z.object({
  userId: z.number().optional(),
});

// Multi select
const multiSelectSchema = z.object({
  roleIds: z.array(z.number()).optional(),
});
```

### Form Default Values
```typescript
const form = useForm({
  resolver: zodResolver(schema),
  defaultValues: {
    userId: undefined,        // Single select
    roleIds: undefined,       // Multi select
  },
});
```

### Cleaning Form Data
```typescript
const handleSubmit = (data: FormData) => {
  const cleaned = {
    ...data,
    // Single select - already clean
    userId: data.userId,
    
    // Multi select - check for empty array
    roleIds: data.roleIds && data.roleIds.length > 0 
      ? data.roleIds 
      : undefined,
  };
  
  // Send to API
};
```