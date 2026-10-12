import { ControlCenter } from "@/components/control-center";
import { loadDashboard } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function Home() {
  const data = await loadDashboard();
  return <ControlCenter data={data} />;
}
