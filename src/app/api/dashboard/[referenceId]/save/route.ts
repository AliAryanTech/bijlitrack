import { NextRequest, NextResponse } from 'next/server';
import { connectDB } from '@/lib/server/db';
import {
  Reference,
  ConsumerSnapshot,
  BillHistory,
  OutageHistory,
} from '@/lib/server/models';
import mongoose from 'mongoose';
import { verifyAuth } from '@/lib/server/auth';

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ referenceId: string }> }
) {
  try {
    const authUser = verifyAuth(req);
    await connectDB();

    const { referenceId } = await params;
    if (!mongoose.Types.ObjectId.isValid(referenceId)) {
      return NextResponse.json({ message: 'Invalid reference ID format' }, { status: 400 });
    }

    const body = await req.json();
    if (JSON.stringify(body).length > 512 * 1024) {
      return NextResponse.json({ message: 'Payload exceeds allowed limit (512KB)' }, { status: 413 });
    }

    const { consumerInfo, billingInfo, outageInfo } = body;

    if (outageInfo?.days && Object.keys(outageInfo.days).length > 60) {
      return NextResponse.json({ message: 'Outage history days exceed limit (max 60 days)' }, { status: 400 });
    }

    const reference = await Reference.findOne({ _id: referenceId, userId: authUser.id });
    if (!reference) {
      return NextResponse.json(
        { message: 'Reference not found or not authorized' },
        { status: 404 }
      );
    }

    if (!consumerInfo && !billingInfo && !outageInfo) {
      return NextResponse.json(
        { message: 'No data provided to save' },
        { status: 400 }
      );
    }

    // 1. Save Snapshot
    const snapshot = new ConsumerSnapshot({
      userId: authUser.id,
      referenceId: reference._id,
      consumerInfo: consumerInfo || null,
      billingInfo: billingInfo || null,
      feederInfo: outageInfo
        ? {
            code: outageInfo.feederCode,
            name: outageInfo.feederName,
            grid: outageInfo.gridStation,
          }
        : null,
      loadManagementInfo: outageInfo || null,
      outageInfo: outageInfo || null,
      scrapedAt: new Date(),
    });
    await snapshot.save();

    // 2. Upsert bill history if billing data provided
    if (billingInfo?.histInfo) {
      const hist = billingInfo.histInfo;
      const promises = [];
      for (let i = 1; i <= 13; i++) {
        const month = hist[`gbHistMM${i}`];
        const amount = hist[`gbHistAssment${i}`];
        const payment = hist[`payment${i}`];
        if (month) {
          promises.push(
            BillHistory.findOneAndUpdate(
              { referenceId: reference._id, billMonth: month },
              {
                userId: authUser.id,
                amountDue: parseFloat(amount) || 0,
                status: payment ? 'Paid' : 'Unpaid',
                scrapedAt: new Date(),
              },
              { upsert: true }
            )
          );
        }
      }
      await Promise.all(promises);
    }

    // 3. Save outage records if outage data provided
    if (outageInfo?.days) {
      const outagePromises = [];
      for (const [dateStr, dayData] of Object.entries<any>(outageInfo.days)) {
        const dayDate = new Date(dateStr + 'T00:00:00');
        const nextDay = new Date(dayDate.getTime() + 24 * 60 * 60 * 1000);
        outagePromises.push(
          OutageHistory.findOneAndUpdate(
            { referenceId: reference._id, date: { $gte: dayDate, $lt: nextDay } },
            {
              userId: authUser.id,
              referenceId: reference._id,
              feederCode: outageInfo.feederCode,
              feederName: outageInfo.feederName,
              date: dayDate,
              feederStatus: outageInfo.currentStatus,
              hourlyOutageMinutes: dayData.hourlyOutageMinutes || [],
              hourlyStatus: dayData.hourlyStatus || [],
              totalOutageMinutes: dayData.totalOutageMinutes || 0,
              actualOutageHours: dayData.totalOutageHours || 0,
              scrapedAt: new Date(),
            },
            { upsert: true }
          )
        );
      }
      await Promise.all(outagePromises);
    }

    reference.lastCheckedAt = new Date();
    if (outageInfo?.feederCode) {
      reference.feederCode = outageInfo.feederCode;
    }
    await reference.save();

    return NextResponse.json({
      message: 'Data saved successfully',
      lastUpdated: snapshot.scrapedAt,
    });
  } catch (error: any) {
    const status = error.message.includes('Not authorized') ? 401 : 500;
    return NextResponse.json(
      { message: error.message || 'Error saving data' },
      { status }
    );
  }
}
