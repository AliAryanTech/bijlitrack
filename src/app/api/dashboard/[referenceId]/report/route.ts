import { NextRequest, NextResponse } from 'next/server';
import { connectDB } from '@/lib/server/db';
import { Reference, AnalysisReport } from '@/lib/server/models';
import mongoose from 'mongoose';
import { verifyAuth } from '@/lib/server/auth';

export async function GET(
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

    const reference = await Reference.findOne({ _id: referenceId, userId: authUser.id });
    if (!reference) {
      return NextResponse.json(
        { message: 'Reference not found or not authorized' },
        { status: 404 }
      );
    }

    const report = await AnalysisReport.findOne({ referenceId }).sort({ generatedAt: -1 });
    if (!report) {
      return NextResponse.json({ message: 'No report generated yet.' });
    }

    return NextResponse.json(report);
  } catch (error: any) {
    const status = error.message.includes('Not authorized') ? 401 : 500;
    return NextResponse.json(
      { message: error.message || 'Error fetching report' },
      { status }
    );
  }
}
