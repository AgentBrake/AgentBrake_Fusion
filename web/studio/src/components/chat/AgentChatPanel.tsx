import { SendHorizontal } from "lucide-react";
import { FormEvent, useState } from "react";
import type { ChatMessage } from "../../types";

const roleLabels: Record<ChatMessage["role"], string> = {
  system: "系统",
  user: "用户",
  assistant: "智能体"
};

export function AgentChatPanel({
  messages,
  disabled = false,
  onSend
}: {
  messages: ChatMessage[];
  disabled?: boolean;
  onSend: (text: string) => Promise<void>;
}) {
  const [text, setText] = useState("");

  async function submit(event: FormEvent) {
    event.preventDefault();
    const next = text.trim();
    if (!next || disabled) return;
    setText("");
    await onSend(next);
  }

  return (
    <section className="card chat-panel">
      <div className="section-heading compact">
        <h2>本地 OpenClaw 对话</h2>
        <p>发送任务后，OpenClaw 产生的候选工具动作会先停在 AgentBrake-Fusion 执行前网关。</p>
      </div>
      <div className="chat-scroll">
        {messages.map((message) => (
          <div className={`chat-bubble ${message.role}`} key={message.id}>
            <span>{roleLabels[message.role]}</span>
            <p>{message.text}</p>
          </div>
        ))}
      </div>
      <form className="chat-input" onSubmit={submit}>
        <input
          data-testid="chat-input"
          value={text}
          onChange={(event) => setText(event.target.value)}
          placeholder={disabled ? "正在读取外部材料并执行安全裁决..." : "输入要交给本地 OpenClaw 的任务..."}
          disabled={disabled}
        />
        <button data-testid="send-button" className="primary" type="submit" disabled={disabled}>
          <SendHorizontal size={16} /> 发送
        </button>
      </form>
    </section>
  );
}
