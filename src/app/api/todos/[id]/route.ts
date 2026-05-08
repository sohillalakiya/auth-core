import { NextRequest, NextResponse } from 'next/server';
import { withDPoP } from '@/lib/oidc/dpop-middleware';
import { getSession } from '@/lib/oidc/session';

const dpopEnabled =
  process.env.DPOP_ENABLED === 'true' || process.env.DPOP_ENABLED === '1';

type RouteContext = { params: Promise<{ id: string }> };

async function patchHandler(request: NextRequest, { params }: RouteContext): Promise<NextResponse> {
  const session = await getSession();
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { id } = await params;

  let body: { text?: string; completed?: boolean; createdAt?: number };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 });
  }

  return NextResponse.json({
    todo: { id, ...body },
  });
}

async function deleteHandler(_request: NextRequest, { params }: RouteContext): Promise<NextResponse> {
  const session = await getSession();
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const { id } = await params;
  return NextResponse.json({ id });
}

export const PATCH = withDPoP({
  enabled: dpopEnabled,
  required: dpopEnabled,
  getJkt: async () => (await getSession())?.dpop_jkt,
  getAccessToken: async () => (await getSession())?.access_token,
})(patchHandler);

export const DELETE = withDPoP({
  enabled: dpopEnabled,
  required: dpopEnabled,
  getJkt: async () => (await getSession())?.dpop_jkt,
  getAccessToken: async () => (await getSession())?.access_token,
})(deleteHandler);
