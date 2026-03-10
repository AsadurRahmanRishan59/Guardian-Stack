"use client";
import React, { useEffect } from "react";
import { Resolver, useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Loader2,
  Save,
  Car,
  Shield,
  Flame,
  Zap,
  Wind,
  Mountain,
} from "lucide-react";
import {
  MotorTariffRatesPatchFormValues,
  motorTariffRatesPatchSchema,
} from "../motor.tariff.schema";
import {
  useGetMotorTariffByTariffKey,
  usePatchMotorTariffRates,
} from "../motor.tariff.react-query";
import {
  Dialog,
  DialogBody,
  DialogClose,
  DialogContent,
} from "@/components/ui/custom-dialog";
import { isServerError } from "@/lib/error-handling";

interface MotorTariffPatchModalProps {
  tariffKey: number;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const MotorTariffPatchModal: React.FC<MotorTariffPatchModalProps> = ({
  tariffKey,
  open,
  onOpenChange,
}) => {
  const {
    data: motorTariffData,
    isLoading,
    error,
  } = useGetMotorTariffByTariffKey(open && tariffKey ? tariffKey : undefined);

  const patchMutation = usePatchMotorTariffRates();

  const resolver = zodResolver(
    motorTariffRatesPatchSchema
  ) as unknown as Resolver<MotorTariffRatesPatchFormValues>;
  const form = useForm<MotorTariffRatesPatchFormValues>({
    resolver: resolver,
    defaultValues: {
      ownDpBasic: motorTariffData?.ownDpBasic ?? undefined,
      fullInsValue: motorTariffData?.fullInsValue ?? undefined,
      actLiability: motorTariffData?.actLiability ?? undefined,
      fire: motorTariffData?.fire ?? undefined,
      theft: motorTariffData?.theft ?? undefined,
      cyclone: motorTariffData?.cyclone ?? undefined,
      earthquake: motorTariffData?.earthquake ?? undefined,
      others: motorTariffData?.others ?? undefined,
    },
    mode: "onBlur",
  });

  const { control, reset, setError } = form;

  // Update form values when data is loaded
  useEffect(() => {
    if (motorTariffData) {
      form.reset({
        ownDpBasic: motorTariffData.ownDpBasic || 0,
        fullInsValue: motorTariffData.fullInsValue || 0,
        actLiability: motorTariffData.actLiability || 0,
        fire: motorTariffData.fire || 0,
        theft: motorTariffData.theft || 0,
        cyclone: motorTariffData.cyclone || 0,
        earthquake: motorTariffData.earthquake || 0,
        others: motorTariffData.others || 0,
      });
    }
  }, [motorTariffData, form]);

  const onSubmit = async (data: MotorTariffRatesPatchFormValues) => {
    try {
      await patchMutation.mutateAsync({
        tariffKey: tariffKey,
        rates: data,
      });

      // Close modal on success
      onOpenChange(false);
    } catch (error) {
      if (isServerError(error)) {
        if (
          error.data &&
          typeof error.data === "object" &&
          error.data !== null
        ) {
          const dataObj = error.data as Record<string, string>;
          Object.entries(dataObj).forEach(([field, message]) => {
            // Only set error if the field exists in the form
            if (field in form.getValues()) {
              setError(field as keyof MotorTariffRatesPatchFormValues, {
                type: "server",
                message: message,
              });
            }
          });

          // If there are no field-specific errors, show a general error
          if (Object.keys(dataObj).length === 0) {
            setError("ownDpBasic", {
              type: "server",
              message: "Server error occurred. Please try again.",
            });
          }
        }
      } else {
        console.error("Form submission error:", error);
        // Handle client-side errors
        setError("root.serverError", {
          type: "server",
          message: "An unexpected error occurred. Please try again.",
        });
      }
    }
  };

  const rateFields = [
    {
      name: "ownDpBasic" as const,
      label: "Own Damage Basic",
      icon: Car,
      suffix: "BDT",
    },
    {
      name: "fullInsValue" as const,
      label: "Full Insurance Value",
      icon: Shield,
      suffix: "%",
    },
    {
      name: "actLiability" as const,
      label: "Act Liability",
      icon: Shield,
      suffix: "BDT",
    },
    {
      name: "fire" as const,
      label: "Fire Coverage",
      icon: Flame,
      suffix: "%",
    },
    {
      name: "theft" as const,
      label: "Theft Coverage",
      icon: Zap,
      suffix: "%",
    },
    {
      name: "cyclone" as const,
      label: "Cyclone Coverage",
      icon: Wind,
      suffix: "%",
    },
    {
      name: "earthquake" as const,
      label: "Earthquake Coverage",
      icon: Mountain,
      suffix: "%",
    },
    {
      name: "others" as const,
      label: "Other Coverage",
      icon: Shield,
      suffix: "%",
    },
  ];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="full" className="max-h-[90vh] overflow-y-auto">
        <DialogClose />
        {isLoading ? (
          <DialogBody>
            <div className="flex items-center justify-center p-8">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
              <span className="ml-3 text-lg">Loading tariff details...</span>
            </div>
          </DialogBody>
        ) : error || !motorTariffData ? (
          <DialogBody>
            <div className="flex items-center justify-center p-8 text-center">
              {/* <p className="text-red-500 text-lg mb-2">
                Error loading tariff details
              </p> */}
              <p className="text-destructive font-bold">
                {error?.message ||
                  "Failed to load tariff data. Please try again."}
              </p>
            </div>
          </DialogBody>
        ) : (
          <div className="max-w-4xl mx-auto p-8 space-y-6">
            {/* Header Section */}
            <Card className="shadow-sm border border-gray-200">
              <CardHeader className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                {/* Left side */}
                <div className="flex items-center gap-2">
                  <div className="flex items-center justify-center p-2 rounded-xl  text-blue-600">
                    <Car className="h-5 w-5 text-primary" />
                  </div>
                  <CardTitle className="text-base sm:text-lg font-semibold tracking-tight">
                    Update Motor Tariff Rate
                  </CardTitle>
                </div>

                {/* Right side */}
                <div className="px-3 py-1 rounded-lg bg-primary text-gray-700 font-mono text-xs sm:text-sm">
                  Tariff Key&nbsp;
                  <span className="font-semibold text-gray-900">
                    #{tariffKey}
                  </span>
                </div>
              </CardHeader>
            </Card>

            {/* Editable Rates Form */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-lg">
                  <Alert>
                    <Shield className="h-4 w-4 text-center" />
                    <AlertDescription>
                      Changes will be applied immediately after submission.
                      Please review all values carefully.
                    </AlertDescription>
                  </Alert>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <Form {...form}>
                  <form
                    onSubmit={form.handleSubmit(onSubmit)}
                    className="space-y-6"
                  >
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      {rateFields.map((fField) => {
                        const IconComponent = fField.icon;
                        return (
                          <FormField
                            key={fField.name}
                            control={control}
                            name={fField.name}
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel className="flex items-center gap-2">
                                  <IconComponent className="h-4 w-4" />
                                  {fField.label}
                                </FormLabel>
                                <FormControl>
                                  <div className="relative">
                                    <Input
                                      type="number"
                                      step="0.01"
                                      min="0"
                                      placeholder={`Enter ${fField.label.toLowerCase()}`}
                                      className="pr-12"
                                      {...field}
                                    />
                                    <div className="absolute right-3 top-1/2 -translate-y-1/2 text-sm text-muted-foreground">
                                      {fField.suffix}
                                    </div>
                                  </div>
                                </FormControl>
                                <FormMessage />
                              </FormItem>
                            )}
                          />
                        );
                      })}
                    </div>

                    <Separator />

                    <div className="flex justify-end space-x-4">
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => {
                          if (motorTariffData) {
                            reset({
                              ownDpBasic: motorTariffData.ownDpBasic || 0,
                              fullInsValue: motorTariffData.fullInsValue || 0,
                              actLiability: motorTariffData.actLiability || 0,
                              fire: motorTariffData.fire || 0,
                              theft: motorTariffData.theft || 0,
                              cyclone: motorTariffData.cyclone || 0,
                              earthquake: motorTariffData.earthquake || 0,
                              others: motorTariffData.others || 0,
                            });
                          }
                        }}
                        disabled={patchMutation.isPending}
                      >
                        Reset Changes
                      </Button>
                      <Button
                        type="submit"
                        disabled={
                          patchMutation.isPending || !form.formState.isValid
                        }
                        className="min-w-[120px]"
                      >
                        {patchMutation.isPending ? (
                          <>
                            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                            Updating...
                          </>
                        ) : (
                          <>
                            <Save className="mr-2 h-4 w-4" />
                            Update Rates
                          </>
                        )}
                      </Button>
                    </div>
                  </form>
                </Form>
              </CardContent>
            </Card>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
};

export default MotorTariffPatchModal;
