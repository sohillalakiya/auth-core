'use client';

import { useState, useEffect, useCallback } from 'react';
import { useDPoP } from '@/lib/oidc/dpop-hook';
import { dpopFetch } from '@/lib/oidc/dpop-client';

export interface Todo {
  id: string;
  text: string;
  completed: boolean;
  createdAt: number;
}

interface Props {
  accessToken: string;
  dpopEnabled: boolean;
}

const LS_KEY = 'oidc_todos';

function readStorage(): Todo[] {
  try {
    return JSON.parse(localStorage.getItem(LS_KEY) ?? '[]');
  } catch {
    return [];
  }
}

function writeStorage(todos: Todo[]) {
  localStorage.setItem(LS_KEY, JSON.stringify(todos));
}

export default function TodoList({ accessToken, dpopEnabled }: Props) {
  const [todos, setTodos] = useState<Todo[]>([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Always call the hook (rules of hooks); only use its output when dpopEnabled.
  const { isReady } = useDPoP();

  const dpopReady = !dpopEnabled || isReady;

  useEffect(() => {
    setTodos(readStorage());
  }, []);

  const sync = (next: Todo[]) => {
    setTodos(next);
    writeStorage(next);
  };

  // Unified fetch: uses absolute URL + DPoP header when enabled, plain fetch otherwise.
  const call = useCallback(
    (path: string, init: RequestInit = {}): Promise<Response> => {
      if (dpopEnabled) {
        const url = `${window.location.origin}${path}`;
        return dpopFetch(url, { ...init, accessToken });
      }
      return fetch(path, init);
    },
    [dpopEnabled, accessToken],
  );

  const addTodo = async () => {
    const text = input.trim();
    if (!text || busy || !dpopReady) return;
    setBusy(true);
    setError(null);
    try {
      const res = await call('/api/todos', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error ?? `HTTP ${res.status}`);
      }
      const { todo } = await res.json();
      sync([...todos, todo]);
      setInput('');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to add todo');
    } finally {
      setBusy(false);
    }
  };

  const toggleTodo = async (todo: Todo) => {
    if (busy || !dpopReady) return;
    setBusy(true);
    setError(null);
    try {
      const updated = { ...todo, completed: !todo.completed };
      const res = await call(`/api/todos/${todo.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updated),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error ?? `HTTP ${res.status}`);
      }
      const { todo: saved } = await res.json();
      sync(todos.map((t) => (t.id === saved.id ? { ...t, ...saved } : t)));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to update todo');
    } finally {
      setBusy(false);
    }
  };

  const deleteTodo = async (id: string) => {
    if (busy || !dpopReady) return;
    setBusy(true);
    setError(null);
    try {
      const res = await call(`/api/todos/${id}`, { method: 'DELETE' });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error ?? `HTTP ${res.status}`);
      }
      sync(todos.filter((t) => t.id !== id));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to delete todo');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* DPoP status */}
      <div className="flex items-center gap-2">
        <span
          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${
            dpopEnabled
              ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300'
              : 'bg-zinc-100 text-zinc-500 dark:bg-zinc-700 dark:text-zinc-400'
          }`}
        >
          <span
            className={`w-1.5 h-1.5 rounded-full ${
              dpopEnabled
                ? isReady
                  ? 'bg-emerald-500'
                  : 'bg-yellow-500 animate-pulse'
                : 'bg-zinc-400'
            }`}
          />
          {dpopEnabled ? (isReady ? 'DPoP active' : 'DPoP initialising…') : 'DPoP disabled'}
        </span>
      </div>

      {/* Error */}
      {error && (
        <div className="px-4 py-3 rounded-xl bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-sm text-red-700 dark:text-red-300">
          {error}
        </div>
      )}

      {/* Add todo */}
      <div className="flex gap-2">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && addTodo()}
          placeholder="New todo…"
          disabled={busy || !dpopReady}
          className="flex-1 px-4 py-2.5 rounded-xl border border-zinc-200 dark:border-zinc-600 bg-white dark:bg-zinc-800 text-zinc-900 dark:text-zinc-50 placeholder-zinc-400 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50 text-sm"
        />
        <button
          onClick={addTodo}
          disabled={!input.trim() || busy || !dpopReady}
          className="px-4 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium rounded-xl transition-colors text-sm"
        >
          Add
        </button>
      </div>

      {/* Todo list */}
      {todos.length === 0 ? (
        <p className="text-center text-zinc-400 dark:text-zinc-500 text-sm py-8">
          No todos yet. Add one above.
        </p>
      ) : (
        <ul className="space-y-2">
          {todos.map((todo) => (
            <li
              key={todo.id}
              className="flex items-center gap-3 px-4 py-3 bg-white dark:bg-zinc-800 rounded-xl border border-zinc-200 dark:border-zinc-700"
            >
              <button
                onClick={() => toggleTodo(todo)}
                disabled={busy || !dpopReady}
                className={`w-5 h-5 rounded-full border-2 flex-shrink-0 flex items-center justify-center transition-colors disabled:opacity-50 ${
                  todo.completed
                    ? 'bg-emerald-500 border-emerald-500'
                    : 'border-zinc-300 dark:border-zinc-600 hover:border-blue-400'
                }`}
              >
                {todo.completed && (
                  <svg className="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                  </svg>
                )}
              </button>

              <span
                className={`flex-1 text-sm ${
                  todo.completed
                    ? 'line-through text-zinc-400 dark:text-zinc-500'
                    : 'text-zinc-900 dark:text-zinc-50'
                }`}
              >
                {todo.text}
              </span>

              <button
                onClick={() => deleteTodo(todo.id)}
                disabled={busy || !dpopReady}
                className="text-zinc-400 hover:text-red-500 dark:hover:text-red-400 transition-colors disabled:opacity-50"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                </svg>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
