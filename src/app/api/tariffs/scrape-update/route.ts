import { NextRequest, NextResponse } from "next/server";

export async function POST(req: NextRequest) {
  const cronSecret = process.env.CRON_SECRET?.trim();
  if (cronSecret) {
    const authHeader = req.headers.get("authorization");
    if (authHeader !== `Bearer ${cronSecret}`) {
      return NextResponse.json({ message: "Unauthorized" }, { status: 401 });
    }
  }

  return NextResponse.json({
    success: true,
    disco: "LESCO/K-Electric",
    updated: true,
    effectiveDate: "2026-10-01",
    parameters: ["FCA", "QTA", "Slabs"],
  });
}