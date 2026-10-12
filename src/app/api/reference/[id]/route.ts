import { NextRequest, NextResponse } from 'next/server';
import { connectDB } from '@/lib/server/db';
import {
  Reference,
  ConsumerSnapshot,
  BillHistory,
  OutageHistory,
  AnalysisReport,
} from '@/lib/server/models';
import mongoose from 'mongoose';
import { verifyAuth } from '@/lib/server/auth';

export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const authUser = verifyAuth(req);
    await connectDB();

    const { id } = await params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return NextResponse.json({ message: 'Invalid reference ID format' }, { status: 400 });
    }

    const reference = await Reference.findOneAndDelete({
      _id: id,
      userId: authUser.id,
    });

    if (!reference) {
      return NextResponse.json({ message: 'Reference not found' }, { status: 404 });
    }

    await Promise.all([
      ConsumerSnapshot.deleteMany({ referenceId: id }),
      BillHistory.deleteMany({ referenceId: id }),
      OutageHistory.deleteMany({ referenceId: id }),
      AnalysisReport.deleteMany({ referenceId: id }),
    ]);

    return NextResponse.json({ message: 'Reference and all history deleted' });
  } catch (error: any) {
    const status = error.message.includes('Not authorized') ? 401 : 500;
    return NextResponse.json(
      { message: error.message || 'Error deleting reference' },
      { status }
    );
  }
}
