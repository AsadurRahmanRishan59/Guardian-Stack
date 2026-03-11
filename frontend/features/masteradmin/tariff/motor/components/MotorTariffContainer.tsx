// features/masteradmin/tariff/motor/components/MotorTariffContainer.tsx
"use client";

import { useState } from "react";
import { Car, Plus } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

import { MotorTariffList } from "./MotorTariffList";
import { MotorTariffForm } from "./MotorTariffForm";


export function MotorTariffContainer() {
  const [createModalOpen, setCreateModalOpen] = useState(false);

  return (
    <div className="space-y-3">
      {/* ── Page header ── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-lg sm:text-xl font-bold font-head text-t1 flex items-center gap-2">
            <span className="flex items-center justify-center w-8 h-8 rounded-gs bg-brand-soft">
              <Car className="h-4 w-4 text-brand" />
            </span>
            Motor Tariff Management
          </h1>
          <p className="text-sm text-t3 mt-1 ml-10">
            Manage regulated motor insurance tariff rates for Bangladesh
          </p>
        </div>

        <Button
          onClick={() => setCreateModalOpen(true)}
          className="bg-brand hover:bg-brand-hover text-white gap-2 self-start sm:self-auto"
        >
          <Plus className="h-4 w-4" />
          New Tariff
        </Button>
      </div>

      {/* ── Table ── */}
      <MotorTariffList />

      {/* ── Create modal ── */}
      <Dialog open={createModalOpen} onOpenChange={setCreateModalOpen}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto border-gs-line bg-surface-card">
          <DialogHeader>
            <DialogTitle className="text-xl font-head text-t1">
              New Motor Tariff
            </DialogTitle>
            <DialogDescription className="text-t3">
              Fill in the vehicle classification and premium rates. The combination
              of Tariff Type, Group, Vehicle Type, and Category must be unique.
            </DialogDescription>
          </DialogHeader>
          <MotorTariffForm onSuccess={() => setCreateModalOpen(false)} />
        </DialogContent>
      </Dialog>
    </div>
  );
}