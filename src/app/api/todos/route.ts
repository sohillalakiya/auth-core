import { NextRequest, NextResponse } from 'next/server';
import { withDPoP } from '@/lib/oidc/dpop-middleware';
import { getSession } from '@/lib/oidc/session';

const dpopEnabled =
  process.env.DPOP_ENABLED === 'true' || process.env.DPOP_ENABLED === '1';

async function getHandler(_request: NextRequest): Promise<NextResponse> {
  const session = await getSession();
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  // Client is the source of truth (localStorage); we just confirm auth.
  return NextResponse.json({ todos: [] });
}

async function postHandler(request: NextRequest): Promise<NextResponse> {
  const session = await getSession();
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  let body: { text?: string };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 });
  }

  if (!body.text?.trim()) {
    return NextResponse.json({ error: 'Todo text is required' }, { status: 400 });
  }

  return NextResponse.json(
    {
      todo: {
        id: crypto.randomUUID(),
        text: body.text.trim(),
        completed: false,
        createdAt: Date.now(),
      },
    },
    { status: 201 },
  );
}

export const GET = withDPoP({
  enabled: dpopEnabled,
  required: false,
  getJkt: async () => (await getSession())?.dpop_jkt,
  getAccessToken: async () => (await getSession())?.access_token,
})(getHandler);

export const POST = withDPoP({
  enabled: dpopEnabled,
  required: dpopEnabled,
  getJkt: async () => (await getSession())?.dpop_jkt,
  getAccessToken: async () => (await getSession())?.access_token,
})(postHandler);
