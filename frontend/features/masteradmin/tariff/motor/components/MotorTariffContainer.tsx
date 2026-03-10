"use client";

import React, { useState } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Building2, List, Plus, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ComboboxSelect } from "@/components//table/combobox-select";
import { Card, CardContent } from "@/components/ui/card";
// import { useQueryMotorTariffList } from "@/resource/motorTariff-list/motorTariffList";
import {
  useCreateMotorTariff,
  useGetMotorTariffByTariffKey,
  useUpdateMotorTariff,
} from "../motor.tariff.react-query";
import { MotorTariffRequestFormValues } from "../motor.tariff.schema";
import { MotorTariffRequest } from "../motor.tariff.types";
import { ServerSuccessResponse } from "@/types/common.types";
import { MotorTariffForm } from "./MotorTariffForm";
import { MotorTariffList } from "./MotorTariffList";
import { useQueryMotorTariffList } from "@/resource/tariff-motor-list/motor.tariff";

export const MotorTariffContainer = () => {
  const [activeTab, setActiveTab] = useState("list");
  const [selectedTariffKey, setSelectedTariffKey] = useState<
    number | undefined
  >();
  const {
    motorTariffList,
    isLoading: isMotorTariffListLoading,
    error: motorTariffListError,
    // refetch: motorTariffListRefetch,
  } = useQueryMotorTariffList();

  const createMotorTariffMutation = useCreateMotorTariff();
  const createMotorTariff = createMotorTariffMutation.mutateAsync;
  const isCreating = createMotorTariffMutation.isPending;

  const updateMotorTariffMutation = useUpdateMotorTariff();
  const updateMotorTariff = updateMotorTariffMutation.mutateAsync;
  const isUpdating = updateMotorTariffMutation.isPending;

  // Fetch selected motorTariff details
  const {
    data: selectedMotorTariffData,
    isLoading: isMotorTariffDataLoading,
    refetch: refetchMotorTariffData,
  } = useGetMotorTariffByTariffKey(selectedTariffKey);

  // Handle form submission
  const handleFormSubmit = async (
    values: MotorTariffRequestFormValues
  ): Promise<ServerSuccessResponse<MotorTariffRequest> | null> => {
    try {
      if (selectedTariffKey) {
        // Update existing motorTariff
        const response = await updateMotorTariff({
          tariffKey: selectedTariffKey,
          motorTariffRequest: values,
        });
        return response;
      } else {
        // Create new motorTariff
        const response = await createMotorTariff(values);
        return response;
      }
    } catch (error) {
      throw error; // Re-throw to let the form handle it
    }
  };
  // Handle branch selection
  const handleMotorTariffSelection = (tariffKey: number | undefined) => {
    setSelectedTariffKey(tariffKey);
  };

  // Handle clear selection (create new branch)
  const handleClearSelection = () => {
    setSelectedTariffKey(undefined);
  };

  // Refresh branch data
  const handleRefreshBranchData = () => {
    if (selectedTariffKey) {
      refetchMotorTariffData();
    }
  };

  const isLoading =
    isCreating ||
    isUpdating ||
    (!!selectedTariffKey && isMotorTariffDataLoading);

  const mode = selectedTariffKey ? "edit" : "create";

  return (
    <div className="min-h-screen ">
      <div className="max-w-7xl mx-auto ">
        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <div className="mb-8">
            <TabsList className="grid w-full max-w-md grid-cols-2 mx-auto bg-white dark:bg-gray-800 shadow-sm border dark:border-gray-700">
              <TabsTrigger
                value="form"
                className="flex items-center gap-2 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground transition-all duration-200"
              >
                <Plus className="h-4 w-4" />
                Add MotorTariff
              </TabsTrigger>
              <TabsTrigger
                value="list"
                className="flex items-center gap-2 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground transition-all duration-200"
              >
                <List className="h-4 w-4" />
                MotorTariff List
              </TabsTrigger>
            </TabsList>
          </div>

          <TabsContent value="form" className="space-y-6">
            <Card>
              <CardContent className="p-0">
                <div className="py-6 px-6">
                  {/* Page Header */}
                  <div className="mb-6 text-center">
                    <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2">
                      Motor Tariff Management
                    </h1>
                    <p className="text-muted-foreground">
                      Select an motor tariff to update or leave empty to create a
                      new one
                    </p>
                  </div>

                  {/* Branch Selector */}
                  <div className="bg-white dark:bg-gray-900 rounded-lg border p-6 shadow-sm mb-6">
                    <div className="flex items-center gap-4">
                      <div className="flex items-center gap-2 text-sm font-medium text-gray-700 dark:text-gray-200">
                        <Building2 className="h-4 w-4" />
                      </div>

                      <div className="flex-1 flex gap-2">
                        <div className="w-2/3 ">
                          <ComboboxSelect
                            items={motorTariffList}
                            value={selectedTariffKey}
                            onChange={handleMotorTariffSelection}
                            displayField="tariffKey"
                            valueField="tariffKey"
                            placeholder="Select Motor Tariff to update"
                            loading={isMotorTariffListLoading}
                            error={motorTariffListError?.message}
                            tableMode={true}
                            // maxHeight="400px"
                            columns={[
                              {
                                key: "tariffKey",
                                header: "Tariff Key",
                                width: "50px",
                                className:
                                  "whitespace-normal break-words text-sm",
                              },
                              {
                                key: "tariffType",
                                header: "Tariff Type",
                                width: "100px",
                                className: " font-mono text-sm",
                                render: (value) => (
                                  <span className="bg-muted px-2 py-1 rounded text-xs">
                                    #{value}
                                  </span>
                                ),
                              },
                              {
                                key: "typeOfVehicle",
                                header: "Type of Vehicle",
                                width: "150px",
                                className: " font-mono text-sm",
                              },
                              {
                                key: "ownDpBasic",
                                header: "Own Damage",
                                width: "150px",
                                className: " font-mono text-sm",
                              },
                            ]}
                            renderSelected={(motorTariff) => (
                              <div className="flex items-center space-x-2 truncate">
                                <span className="font-medium">
                                  {motorTariff.tariffKey}
                                </span>
                                <span className="text-xs text-muted-foreground">
                                  #{motorTariff.tariffType}
                                </span>
                                
                              </div>
                            )}
                          />
                        </div>

                        {selectedTariffKey && (
                          <>
                            <Button
                              variant="outline"
                              size="icon"
                              onClick={handleRefreshBranchData}
                              disabled={isMotorTariffDataLoading}
                              title="Refresh motorTariff data"
                            >
                              <RefreshCw
                                className={`h-4 w-4 ${
                                  isMotorTariffDataLoading ? "animate-spin" : ""
                                }`}
                              />
                            </Button>
                            <Button
                              variant="outline"
                              onClick={handleClearSelection}
                              disabled={isLoading}
                            >
                              Create New MotorTariff
                            </Button>
                          </>
                        )}
                      </div>
                    </div>

                    {/* Status Information */}
                    <div className="mt-3 text-sm text-muted-foreground">
                      {!selectedTariffKey && (
                        <p className="flex items-center gap-2">
                          <span className="inline-block w-2 h-2 bg-green-500 rounded-full"></span>
                          Ready to create a new motorTariff
                        </p>
                      )}
                      {selectedTariffKey &&
                        !isMotorTariffDataLoading &&
                        selectedMotorTariffData && (
                          <p className="flex items-center gap-2">
                            <span className="inline-block w-2 h-2 bg-blue-500 rounded-full"></span>
                            Editing: {selectedMotorTariffData.tariffKey}
                          </p>
                        )}
                      {selectedTariffKey && isMotorTariffDataLoading && (
                        <p className="flex items-center gap-2">
                          <RefreshCw className="h-3 w-3 animate-spin" />
                          Loading motorTariff data...
                        </p>
                      )}
                    </div>
                  </div>

                  {/* MotorTariff Form */}
                  {(!selectedTariffKey || selectedMotorTariffData) && (
                    <MotorTariffForm
                      mode={mode}
                      onSubmit={handleFormSubmit}
                      isLoading={isLoading}
                      initialData={
                        selectedTariffKey ? selectedMotorTariffData : null
                      }
                      key={selectedTariffKey || "create"} // Force re-render when switching motorTariffs
                    />
                  )}

                  {/* Loading State for MotorTariff Data */}
                  {selectedTariffKey && isMotorTariffDataLoading && (
                    <div className="bg-white dark:bg-gray-900 rounded-lg border p-12 shadow-sm">
                      <div className="flex flex-col items-center justify-center text-center">
                        <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground mb-4" />
                        <h3 className="text-lg font-semibold mb-2">
                          Loading MotorTariff Data
                        </h3>
                        <p className="text-muted-foreground">
                          Please wait while we fetch the motorTariff
                          information...
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="list" className="space-y-6">
            <Card>
              <CardContent className="p-0">
                <div className="text-center mb-6 px-6 pt-6">
                  <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2">
                    MotorTariff Directory
                  </h2>
                  <p className="text-gray-600 dark:text-gray-400 text-md">
                    Manage and view all motorTariffs
                  </p>
                </div>
                <div className="px-6 pb-6">
                  <MotorTariffList />
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default MotorTariffContainer;
