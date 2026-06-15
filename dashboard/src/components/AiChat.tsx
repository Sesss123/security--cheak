import { useState, useRef, useEffect } from 'react';
import { Send, Bot, User } from 'lucide-react';
import { scansApi } from '../services/api';

interface Message {
  role: 'user' | 'assistant';
  content: string;
}

export function AiChat({ scanId }: { scanId: string }) {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      content: "Hi! I'm your AI security analyst. Ask me anything about this scan's findings, vulnerabilities, or how to fix them.",
    },
  ]);
  const [input, setInput]   = useState('');
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const send = async () => {
    if (!input.trim() || loading) return;

    const userMsg: Message = { role: 'user', content: input.trim() };
    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setLoading(true);

    try {
      const history = messages.map((m) => ({ role: m.role, content: m.content }));
      const { reply } = await scansApi.chat(scanId, userMsg.content, history);
      setMessages((prev) => [...prev, { role: 'assistant', content: reply }]);
    } catch {
      setMessages((prev) => [
        ...prev,
        { role: 'assistant', content: 'Sorry, I encountered an error. Please try again.' },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  };

  return (
    <div className="rounded-xl border border-indigo-200 bg-white overflow-hidden">
      <div className="flex items-center gap-2 border-b border-indigo-100 bg-indigo-50 px-4 py-3">
        <Bot className="h-4 w-4 text-indigo-600" />
        <span className="text-sm font-semibold text-indigo-900">AI Security Analyst</span>
        <span className="ml-auto rounded-full bg-green-100 px-2 py-0.5 text-xs text-green-700">Online</span>
      </div>

      {/* Messages */}
      <div className="h-72 overflow-y-auto p-4 space-y-3">
        {messages.map((msg, i) => (
          <div key={i} className={`flex gap-2 ${msg.role === 'user' ? 'justify-end' : ''}`}>
            {msg.role === 'assistant' && (
              <div className="h-7 w-7 flex-shrink-0 flex items-center justify-center rounded-full bg-indigo-100">
                <Bot className="h-4 w-4 text-indigo-600" />
              </div>
            )}
            <div className={`max-w-[80%] rounded-2xl px-4 py-2.5 text-sm ${
              msg.role === 'user'
                ? 'bg-indigo-600 text-white rounded-tr-sm'
                : 'bg-gray-100 text-gray-800 rounded-tl-sm'
            }`}>
              {msg.content}
            </div>
            {msg.role === 'user' && (
              <div className="h-7 w-7 flex-shrink-0 flex items-center justify-center rounded-full bg-gray-200">
                <User className="h-4 w-4 text-gray-600" />
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex gap-2">
            <div className="h-7 w-7 flex-shrink-0 flex items-center justify-center rounded-full bg-indigo-100">
              <Bot className="h-4 w-4 text-indigo-600" />
            </div>
            <div className="rounded-2xl rounded-tl-sm bg-gray-100 px-4 py-3">
              <div className="flex gap-1">
                {[0, 1, 2].map((i) => (
                  <span key={i} className="h-1.5 w-1.5 rounded-full bg-gray-400 animate-bounce"
                    style={{ animationDelay: `${i * 150}ms` }} />
                ))}
              </div>
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Suggestions */}
      <div className="border-t border-gray-100 px-4 py-2 flex gap-2 overflow-x-auto">
        {[
          'What is the most critical issue?',
          'How do I fix the SQL injection?',
          'Explain the CORS issue',
          'Give me a remediation priority list',
        ].map((s) => (
          <button
            key={s}
            onClick={() => { setInput(s); }}
            className="flex-shrink-0 rounded-full border border-gray-200 px-3 py-1 text-xs text-gray-600 hover:bg-gray-50"
          >
            {s}
          </button>
        ))}
      </div>

      {/* Input */}
      <div className="border-t border-gray-100 flex gap-2 p-3">
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKey}
          placeholder="Ask about the vulnerabilities..."
          className="flex-1 rounded-lg border border-gray-200 px-3 py-2 text-sm focus:border-indigo-400 focus:outline-none"
          disabled={loading}
        />
        <button
          onClick={send}
          disabled={loading || !input.trim()}
          className="flex h-9 w-9 items-center justify-center rounded-lg bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50"
        >
          <Send className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}
