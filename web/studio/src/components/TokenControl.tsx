import { useState } from "react";

export function TokenControl() {
  const [open, setOpen] = useState(false);
  const [token, setToken] = useState(localStorage.getItem("agentbrakeFusionToken") || "agentbrake-fusion-local");

  function save() {
    localStorage.setItem("agentbrakeFusionToken", token);
    window.location.reload();
  }

  return (
    <div className="token-control">
      <button onClick={() => setOpen(!open)}>令牌</button>
      {open ? (
        <div className="token-popover">
          <label>
            Studio Bearer 令牌
            <input value={token} onChange={(event) => setToken(event.target.value)} />
          </label>
          <button className="primary" onClick={save}>保存并刷新</button>
        </div>
      ) : null}
    </div>
  );
}
