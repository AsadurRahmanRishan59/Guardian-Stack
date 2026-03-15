// app/admin/master-data/tariffs/motor/rate-table/page.tsx  (or wherever the route lives)
// This is the page-level container — import MotorTariffList here.

import { MotorTariffContainer } from "@/features/masteradmin/tariff/motor/components/MotorTariffContainer";
// import { MotorTariffList } from "@/features/masteradmin/tariff/motor/components/MotorTariffList";

export default function MotorTariffPage() {
  return <MotorTariffContainer />;
}
