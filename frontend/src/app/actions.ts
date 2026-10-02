'use server';

import { auth } from '@clerk/nextjs/server';
import { prisma } from '../lib/prisma';

export async function saveThreatLog(data: any) {
  try {
    const { userId } = await auth();
    if (!userId) return null; // history is per-user, so don't store orphan rows

    return await prisma.threatLog.create({
      data: {
        url: String(data?.url ?? 'Unknown Target').slice(0, 2048),
        riskLevel: data?.risk_level ?? data?.analysis?.exfiltration_level ?? 'UNKNOWN',
        networkReqs: data?.network_logs?.length ?? 0,
        analysis: {
          ...(data?.analysis ?? {}),
          threat_score: data?.threat_score ?? 0,
          score_breakdown: data?.score_breakdown ?? [],
          final_url: data?.final_url ?? null,
          runtime_events: data?.runtime_events ?? [],
          interactions: data?.interactions ?? [],
          third_party_domains: data?.third_party_domains ?? [],
          visual_frames: data?.visual_frames ?? [], // captions only, images already stripped
        },
        userId,
      },
    });
  } catch (error) {
    console.error('Failed to save threat log:', error);
    return null;
  }
}

export async function getThreatLogs() {
  try {
    const { userId } = await auth();
    if (!userId) return [];

    return await prisma.threatLog.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
    });
  } catch (error) {
    console.error('Failed to fetch threat logs:', error);
    return [];
  }
}

export async function getThreatLogById(id: string) {
  try {
    const { userId } = await auth();
    if (!userId) return null;

    // findFirst with userId = only the owner can open this report
    return await prisma.threatLog.findFirst({ where: { id, userId } });
  } catch (error) {
    console.error('Failed to fetch threat log:', error);
    return null;
  }
} 