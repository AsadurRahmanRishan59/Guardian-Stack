"use client";
import { FC } from "react";
import { Resolver, useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import {
  Car,
  Loader2,
  Shield,
  DollarSign,
  Flame,
  AlertTriangle,
  Wind,
  Zap,
  MoreHorizontal,
  CheckCircle,
} from "lucide-react";
import { isServerError } from "@/lib/error-handling";
import { MotorTariffFormProps } from "../motor.tariff.types";
import {
  motorTariffRequestFormSchema,
  MotorTariffRequestFormValues,
} from "../motor.tariff.schema";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Tooltip,
  TooltipTrigger,
  TooltipContent,
} from "@/components/ui/tooltip";

const TARIFF_TYPES = [
  "Private Vehicle",
  "Motor Cycle",
  "Commercial Vehicle",
] as const;

const VEHICLE_GROUPS = [
  "Passenger Vehicle/Goods Carrying",
  "Trailer",
  "Class A Goods Carrying Vehicles",
  "Class B(1,0) Goods Carrying Vehicles",
  "Class B(1,0) Passenger Carrying Vehicles",
  "Class B(2,0) Passenger Carrying Vehicles",
  "Class C Passenger Carrying Vehicles",
  "Class D Miscellaneous & Special Types of Vehicles",
  "Auto Cycles or Mechanically Assisted Pedal Cycles",
  "MotorCycle/Scooter",
] as const;

export const MotorTariffForm: FC<MotorTariffFormProps> = ({
  onSubmit,
  isLoading,
  initialData = null,
  mode = "create",
}) => {
  const resolver = zodResolver(motorTariffRequestFormSchema) as unknown as Resolver<MotorTariffRequestFormValues>;
  const form = useForm<MotorTariffRequestFormValues>({
    resolver: resolver,
    defaultValues: {
      tariffType: initialData?.tariffType ?? undefined,
      groupOfVehicle: initialData?.groupOfVehicle ?? undefined,
      typeOfVehicle: initialData?.typeOfVehicle ?? "",
      category: initialData?.category ?? "",
      ownDpBasic: initialData?.ownDpBasic ?? undefined,
      fullInsValue: initialData?.fullInsValue ?? undefined,
      actLiability: initialData?.actLiability ?? undefined,
      fire: initialData?.fire ?? undefined,
      theft: initialData?.theft ?? undefined,
      cyclone: initialData?.cyclone ?? undefined,
      earthquake: initialData?.earthquake ?? undefined,
      others: initialData?.others ?? undefined,
      isActive: initialData?.isActive ?? true,
    },
    mode: "onBlur",
  });

  const { control, reset, setError } = form;

  const handleSubmit = async (values: MotorTariffRequestFormValues) => {
    try {
      await onSubmit(values);
      if (mode === "create") reset();
    } catch (error) {
      if (isServerError(error)) {
        if (
          error.data &&
          typeof error.data === "object" &&
          error.data !== null
        ) {
          const dataObj = error.data as Record<string, string>;
          Object.entries(dataObj).forEach(([field, message]) =>
            setError(field as keyof MotorTariffRequestFormValues, {
              type: "server",
              message,
            })
          );
        }
      } else {
        setError("tariffType", {
          type: "server",
          message: "An unexpected error occurred",
        });
      }
    }
  };

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(handleSubmit)} className="space-y-6">
        <div className="rounded-md border p-8 dark:border-gray-700 bg-white dark:bg-gray-900 shadow-sm">
          <div className="space-y-6">
            <h3 className="text-lg font-medium text-gray-700 dark:text-gray-200">
              {mode === "create" ? "Add New Motor Tariff" : "Update Motor Tariff"}
            </h3>

            {/* Basic Info */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Tariff Type */}
              <FormField
                control={control}
                name="tariffType"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel className="flex items-center gap-2">
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="flex items-center gap-2">
                            <Car className="h-4 w-4" />
                            <span>Tariff Type</span>
                          </span>
                        </TooltipTrigger>
                        <TooltipContent>
                          Required. Select the type of vehicle tariff.
                        </TooltipContent>
                      </Tooltip>
                    </FormLabel>

                    <Select
                      value={field.value ?? ""}
                      onValueChange={(v) => field.onChange(v)}
                      disabled={isLoading}
                    >
                      <FormControl>
                        <SelectTrigger className="bg-background/50 backdrop-blur-sm transition-shadow duration-200 focus:shadow-lg">
                          <SelectValue placeholder="Select tariff type" />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        {TARIFF_TYPES.map((t) => (
                          <SelectItem key={t} value={t}>
                            {t}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>

                    <FormMessage />
                  </FormItem>
                )}
              />

              {/* Group of Vehicle */}
              <FormField
                control={control}
                name="groupOfVehicle"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel className="flex items-center gap-2">
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="flex items-center gap-2">
                            <Shield className="h-4 w-4" />
                            <span>Group of Vehicle</span>
                          </span>
                        </TooltipTrigger>
                        <TooltipContent>
                          Required. Select the vehicle group category.
                        </TooltipContent>
                      </Tooltip>
                    </FormLabel>

                    <Select
                      value={field.value ?? ""}
                      onValueChange={(v) => field.onChange(v)}
                      disabled={isLoading}
                    >
                      <FormControl>
                        <SelectTrigger className="bg-background/50 backdrop-blur-sm transition-shadow duration-200 focus:shadow-lg">
                          <SelectValue placeholder="Select vehicle group" />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        {VEHICLE_GROUPS.map((g) => (
                          <SelectItem key={g} value={g}>
                            {g}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>

                    <FormMessage />
                  </FormItem>
                )}
              />

              {/* Type of Vehicle */}
              <FormField
                control={control}
                name="typeOfVehicle"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel className="flex items-center gap-2">
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="flex items-center gap-2">
                            <Car className="h-4 w-4" />
                            <span>Type of Vehicle</span>
                          </span>
                        </TooltipTrigger>
                        <TooltipContent>
                          Required. Specify the specific type of vehicle (max 500 characters).
                        </TooltipContent>
                      </Tooltip>
                    </FormLabel>

                    <FormControl>
                      <Input
                        placeholder="e.g., Sedan, SUV, Hatchback"
                        {...field}
                        disabled={isLoading}
                        className="bg-background/50 backdrop-blur-sm transition-shadow duration-200 focus:shadow-lg"
                      />
                    </FormControl>

                    <FormMessage />
                  </FormItem>
                )}
              />

              {/* Category */}
              <FormField
                control={control}
                name="category"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel className="flex items-center gap-2">
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="flex items-center gap-2">
                            <Shield className="h-4 w-4" />
                            <span>Category</span>
                          </span>
                        </TooltipTrigger>
                        <TooltipContent>
                          Required. Vehicle category details like engine capacity (max 500 characters).
                        </TooltipContent>
                      </Tooltip>
                    </FormLabel>

                    <FormControl>
                      <Input
                        placeholder="e.g., 1500 CC, Manual Transmission"
                        {...field}
                        disabled={isLoading}
                        className="bg-background/50 backdrop-blur-sm transition-shadow duration-200 focus:shadow-lg"
                      />
                    </FormControl>

                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            {/* Financial Info */}
            <div className="space-y-4">
              <h4 className="text-md font-medium text-gray-600 dark:text-gray-300 border-b pb-2">
                Coverage & Rates
              </h4>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {/* ownDpBasic */}
                <FormField
                  control={control}
                  name="ownDpBasic"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="flex items-center gap-2">
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span className="flex items-center gap-2">
                              <DollarSign className="h-4 w-4" />
                              <span>Own Damage Basic</span>
                            </span>
                          </TooltipTrigger>
                          <TooltipContent>
                            Basic own damage coverage amount (0-50,000).
                          </TooltipContent>
                        </Tooltip>
                      </FormLabel>

                      <FormControl>
                        <Input
                          type="number"
                          step="0.01"
                          min="0"
                          max="50000"
                          placeholder="0.00"
                          {...field}
                          disabled={isLoading}
                          className="bg-background/50 backdrop-blur-sm transition-shadow duration-200 focus:shadow-lg"
                        />
                      </FormControl>

                      <FormMessage />
                    </FormItem>
                  )}
                />

                {/* fullInsValue */}
                <FormField
                  control={control}
                  name="fullInsValue"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="flex items-center gap-2">
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span className="flex items-center gap-2">
                              <Shield className="h-4 w-4" />
                              <span>Full Insurance Value (%)</span>
                            </span>
                          </TooltipTrigger>
                          <TooltipContent>
                            Full insurance coverage percentage (0-100%).
                          </TooltipContent>
                        </Tooltip>
                      </FormLabel>

                      <FormControl>
                        <Input
                          type="number"
                          step="0.01"
                          min="0"
                          max="100"
                          placeholder="0.00"
                          {...field}
                          disabled={isLoading}
                          className="bg-background/50 backdrop-blur-sm transition-shadow duration-200 focus:shadow-lg"
                        />
                      </FormControl>

                      <FormMessage />
                    </FormItem>
                  )}
                />

                {/* actLiability */}
                <FormField
                  control={control}
                  name="actLiability"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="flex items-center gap-2">
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span className="flex items-center gap-2">
                              <AlertTriangle className="h-4 w-4" />
                              <span>Act Liability</span>
                            </span>
                          </TooltipTrigger>
                          <TooltipContent>
                            Third party liability coverage (0-10,000).
                          </TooltipContent>
                        </Tooltip>
                      </FormLabel>

                      <FormControl>
                        <Input
                          type="number"
                          step="0.01"
                          min="0"
                          max="10000"
                          placeholder="0.00"
                          {...field}
                          disabled={isLoading}
                          className="bg-background/50 backdrop-blur-sm transition-shadow duration-200 focus:shadow-lg"
                        />
                      </FormControl>

                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>
            </div>

            {/* Risk Coverage (explicit fields to avoid TS union issue) */}
            <div className="space-y-4">
              <h4 className="text-md font-medium text-gray-600 dark:text-gray-300 border-b pb-2">
                Risk Coverage (%)
              </h4>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {/* Fire */}
                <FormField
                  control={control}
                  name="fire"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="flex items-center gap-2">
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span className="flex items-center gap-2">
                              <Flame className="h-4 w-4 text-red-500" />
                              <span>Fire Coverage (%)</span>
                            </span>
                          </TooltipTrigger>
                          <TooltipContent>
                            Fire damage coverage percentage (0-100%).
                          </TooltipContent>
                        </Tooltip>
                      </FormLabel>
                      <FormControl>
                        <Input
                          type="number"
                          step="0.01"
                          min="0"
                          max="100"
                          placeholder="0.00"
                          {...field}
                          disabled={isLoading}
                          className="bg-background/50 backdrop-blur-sm transition-shadow duration-200 focus:shadow-lg"
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                {/* Theft */}
                <FormField
                  control={control}
                  name="theft"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="flex items-center gap-2">
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span className="flex items-center gap-2">
                              <Shield className="h-4 w-4 text-orange-500" />
                              <span>Theft Coverage (%)</span>
                            </span>
                          </TooltipTrigger>
                          <TooltipContent>
                            Theft protection coverage percentage (0-100%).
                          </TooltipContent>
                        </Tooltip>
                      </FormLabel>
                      <FormControl>
                        <Input
                          type="number"
                          step="0.01"
                          min="0"
                          max="100"
                          placeholder="0.00"
                          {...field}
                          disabled={isLoading}
                          className="bg-background/50 backdrop-blur-sm transition-shadow duration-200 focus:shadow-lg"
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                {/* Cyclone */}
                <FormField
                  control={control}
                  name="cyclone"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="flex items-center gap-2">
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span className="flex items-center gap-2">
                              <Wind className="h-4 w-4 text-blue-500" />
                              <span>Cyclone Coverage (%)</span>
                            </span>
                          </TooltipTrigger>
                          <TooltipContent>
                            Cyclone damage coverage percentage (0-100%).
                          </TooltipContent>
                        </Tooltip>
                      </FormLabel>
                      <FormControl>
                        <Input
                          type="number"
                          step="0.01"
                          min="0"
                          max="100"
                          placeholder="0.00"
                          {...field}
                          disabled={isLoading}
                          className="bg-background/50 backdrop-blur-sm transition-shadow duration-200 focus:shadow-lg"
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                {/* Earthquake */}
                <FormField
                  control={control}
                  name="earthquake"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="flex items-center gap-2">
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span className="flex items-center gap-2">
                              <Zap className="h-4 w-4 text-yellow-500" />
                              <span>Earthquake Coverage (%)</span>
                            </span>
                          </TooltipTrigger>
                          <TooltipContent>
                            Earthquake damage coverage percentage (0-100%).
                          </TooltipContent>
                        </Tooltip>
                      </FormLabel>
                      <FormControl>
                        <Input
                          type="number"
                          step="0.01"
                          min="0"
                          max="100"
                          placeholder="0.00"
                          {...field}
                          disabled={isLoading}
                          className="bg-background/50 backdrop-blur-sm transition-shadow duration-200 focus:shadow-lg"
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                {/* Others */}
                <FormField
                  control={control}
                  name="others"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel className="flex items-center gap-2">
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span className="flex items-center gap-2">
                              <MoreHorizontal className="h-4 w-4 text-gray-500" />
                              <span>Other Coverage (%)</span>
                            </span>
                          </TooltipTrigger>
                          <TooltipContent>
                            Other miscellaneous coverage percentage (0-100%).
                          </TooltipContent>
                        </Tooltip>
                      </FormLabel>
                      <FormControl>
                        <Input
                          type="number"
                          step="0.01"
                          min="0"
                          max="100"
                          placeholder="0.00"
                          {...field}
                          disabled={isLoading}
                          className="bg-background/50 backdrop-blur-sm transition-shadow duration-200 focus:shadow-lg"
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>
            </div>

            {/* Status */}
            <FormField
              name="isActive"
              control={control}
              render={({ field }) => (
                <FormItem className="flex flex-row items-center space-x-3 space-y-0">
                  <FormControl>
                    <Checkbox
                      checked={!!field.value}
                      onCheckedChange={(v) => field.onChange(!!v)}
                      disabled={isLoading}
                    />
                  </FormControl>
                  <div className="space-y-1 leading-none">
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <FormLabel className="flex items-center gap-2 font-medium cursor-pointer">
                          <CheckCircle className="h-4 w-4 text-green-500" />
                          Is Active
                        </FormLabel>
                      </TooltipTrigger>
                      <TooltipContent>
                        Toggle to activate or deactivate this motor tariff.
                      </TooltipContent>
                    </Tooltip>
                  </div>
                  <FormMessage />
                </FormItem>
              )}
            />

            {/* Actions */}
            <div className="flex justify-end space-x-3 pt-4">
              {mode === "create" && (
                <Button
                  type="button"
                  variant="outline"
                  disabled={isLoading}
                  onClick={() => reset()}
                >
                  Reset Form
                </Button>
              )}
              <Button type="submit" disabled={isLoading}>
                {isLoading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    {mode === "create" ? "Adding..." : "Updating..."}
                  </>
                ) : (
                  <>
                    {mode === "create" ? "Add Motor Tariff" : "Update Motor Tariff"}
                  </>
                )}
              </Button>
            </div>
          </div>
        </div>
      </form>
    </Form>
  );
};
