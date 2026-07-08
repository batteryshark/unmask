# Download page

export function DownloadPage() {
  const cmd = "curl -fsSL https://opencode.ai/install | bash";
  return (
    <section>
      <h1>Install</h1>
      <pre>{cmd}</pre>
      <button onClick={() => navigator.clipboard.writeText(cmd)}>Copy</button>
    </section>
  );
}
