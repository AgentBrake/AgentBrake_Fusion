import { CalendarDays, FileText, GitBranch, Globe2, Mail, MessageSquare, Search, ShieldAlert, Table2 } from "lucide-react";
import type { DecisionRun } from "../../types";

type ExternalSource = {
  kind: "email" | "web" | "search" | "chat" | "pdf" | "doc" | "repo" | "calendar" | "sheet" | "unknown";
  title: string;
  channel: string;
  trust: string;
  origin: string;
  content: string;
};

export function ExternalSourceCard({ run }: { run: DecisionRun }) {
  const sources = externalSourcesForRun(run);
  return (
    <section className="external-source-card card" data-testid="external-source-card">
      <div className="external-source-title">
        <div>
          <b>外部不可信来源</b>
          <em>按本轮上下文动态识别，不绑定单一场景</em>
        </div>
        <strong>{sources.length} 类来源</strong>
      </div>
      <div className="external-source-list">
        {sources.map((source) => (
          <article key={source.kind} className="external-source-item">
            <div className="source-card-head">
              <span className="source-icon">{iconFor(source.kind)}</span>
              <div>
                <b>{source.title}</b>
                <em>{source.channel}</em>
              </div>
              <strong>{source.trust}</strong>
            </div>
            <dl>
              <div><dt>来源位置</dt><dd>{source.origin}</dd></div>
              <div><dt>载入内容</dt><dd>{source.content}</dd></div>
            </dl>
          </article>
        ))}
      </div>
      <p><ShieldAlert size={14} /> 这段内容只能提供事实，不能授权工具执行；如果它污染收件人、账户、频道或正文参数，必须进入执行前裁决。</p>
    </section>
  );
}

function externalSourcesForRun(run: DecisionRun): ExternalSource[] {
  const text = `${run.lowTrustContext || ""}\n${run.userTask || ""}\n${run.candidateToolCall?.preview || ""}`;
  const lower = text.toLowerCase();
  const found: ExternalSource[] = [];

  addIf(found, "email", /邮件|email|发件人|from:|smtp|@[a-z0-9.-]+\.[a-z]{2,}/i.test(text), {
    title: "邮件",
    channel: "外部邮件正文 / HTML 注释",
    origin: extractFirst(text, [
      /发件人[:：]\s*([^\n。；;]+)/i,
      /from[:：]\s*([^\n。；;]+)/i,
      /([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})/i
    ])
  }, text);

  addIf(found, "web", /网页|html|http:\/\/|https:\/\/|browser|page|webpage|第三方页面|不可见提示/i.test(text), {
    title: "网页",
    channel: "第三方网页正文 / 隐藏 DOM 文本",
    origin: extractFirst(text, [/(https?:\/\/[^\s，。；;]+)/i, /页面[:：]\s*([^\n。；;]+)/i])
  }, text);

  addIf(found, "search", /搜索结果|搜索摘要|search result|广告商|赞助|sponsored|snippet/i.test(text), {
    title: "搜索结果",
    channel: "第三方搜索片段 / 广告摘要",
    origin: "搜索结果页或广告商摘要"
  }, text);

  addIf(found, "chat", /slack|频道|channel|#\w+|聊天|群消息|direct message|飞书|钉钉/i.test(text), {
    title: "聊天消息",
    channel: "Slack / 群聊 / 频道消息",
    origin: extractFirst(text, [/(#[a-zA-Z0-9_-]+)/, /频道[:：]\s*([^\n。；;]+)/])
  }, text);

  addIf(found, "pdf", /pdf|ocr|账单|invoice|附件|attachment|扫描件/i.test(text), {
    title: "PDF / 附件",
    channel: "上传文件 / OCR 文本 / 附件正文",
    origin: "附件解析结果或 OCR 文本"
  }, text);

  addIf(found, "doc", /协作文档|共享文档|文档正文|评论区|google doc|notion|confluence|访客评论/i.test(text), {
    title: "协作文档",
    channel: "共享文档正文 / 访客评论",
    origin: "外部协作者内容"
  }, text);

  addIf(found, "repo", /readme|issue|pull request|github|gitlab|代码仓库|pr 评论|依赖说明/i.test(lower), {
    title: "代码仓库文本",
    channel: "README / issue / PR 评论",
    origin: "仓库外部文本或评论"
  }, text);

  addIf(found, "calendar", /日历|邀请|calendar|ics|meeting invite|会议邀请/i.test(text), {
    title: "日历邀请",
    channel: "会议邀请 / ICS 描述",
    origin: "外部日历事件正文"
  }, text);

  addIf(found, "sheet", /表格|sheet|spreadsheet|csv|xlsx|单元格/i.test(text), {
    title: "表格数据",
    channel: "电子表格 / CSV / 单元格文本",
    origin: "外部表格内容"
  }, text);

  if (found.length) return found;
  return [{
    kind: "unknown",
    title: "外部材料",
    channel: "尚未识别具体来源类型",
    trust: "低可信 / 待确认",
    origin: "等待读取邮件、网页、PDF、聊天消息、搜索结果或其他外部材料",
    content: shortText(run.lowTrustContext || "本轮尚未读取外部不可信材料。", 260)
  }];
}

function addIf(
  list: ExternalSource[],
  kind: ExternalSource["kind"],
  matched: boolean,
  meta: { title: string; channel: string; origin: string },
  text: string
) {
  if (!matched || list.some((item) => item.kind === kind)) return;
  list.push({
    kind,
    title: `外部不可信来源：${meta.title}`,
    channel: meta.channel,
    trust: "低可信 / 外部内容",
    origin: meta.origin,
    content: shortText(contextAround(text, meta.origin), 260)
  });
}

function iconFor(kind: ExternalSource["kind"]) {
  if (kind === "email") return <Mail size={18} />;
  if (kind === "pdf" || kind === "doc") return <FileText size={18} />;
  if (kind === "search") return <Search size={18} />;
  if (kind === "chat") return <MessageSquare size={18} />;
  if (kind === "repo") return <GitBranch size={18} />;
  if (kind === "calendar") return <CalendarDays size={18} />;
  if (kind === "sheet") return <Table2 size={18} />;
  return <Globe2 size={18} />;
}

function extractFirst(text: string, patterns: RegExp[]) {
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match?.[1]) return shortText(match[1], 90);
  }
  return "外部内容片段";
}

function contextAround(text: string, anchor: string) {
  if (!anchor || anchor === "外部内容片段") return text;
  const index = text.indexOf(anchor);
  if (index < 0) return text;
  return text.slice(Math.max(0, index - 120), Math.min(text.length, index + anchor.length + 160));
}

function shortText(value: string, limit: number) {
  const compact = value.replace(/\s+/g, " ").trim();
  return compact.length > limit ? `${compact.slice(0, limit)}...` : compact;
}
