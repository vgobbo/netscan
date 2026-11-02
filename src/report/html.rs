use crate::model::NetworkTopology;

pub struct HtmlViewerGenerator;

impl HtmlViewerGenerator {
    /// Generates a self-contained, interactive HTML topology viewer with smooth pan/zoom
    /// and client-side vector SVG and high-resolution PNG export buttons.
    pub fn generate(topology: &NetworkTopology, mermaid_src: &str) -> String {
        let clean_mermaid = mermaid_src
            .trim()
            .trim_start_matches("```mermaid")
            .trim_end_matches("```")
            .trim();

        let timestamp_str = topology
            .timestamp
            .format("%Y-%m-%d %H:%M:%S %Z")
            .to_string();

        let subnets_str = topology.local_subnets.join(", ");
        let device_count = topology.devices.len();
        let gw_str = topology
            .primary_gateway
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "N/A".to_string());

        let escaped_mermaid = clean_mermaid
            .replace('\\', "\\\\")
            .replace('`', "\\`")
            .replace('$', "\\$");

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>netscan — Network Topology Viewer</title>
  <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
  <style>
    :root {{
      --bg: #0d1117;
      --surface: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-muted: #8b949e;
      --accent: #58a6ff;
      --accent-hover: #1f6feb;
      --btn-bg: #21262d;
      --btn-hover: #30363d;
      --badge-bg: #1f242c;
    }}
    * {{
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      display: flex;
      flex-direction: column;
      height: 100vh;
      overflow: hidden;
    }}
    header {{
      background-color: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 10px 20px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 15px;
      z-index: 10;
      flex-wrap: wrap;
    }}
    .brand-section {{
      display: flex;
      align-items: center;
      gap: 12px;
    }}
    .brand-title {{
      font-size: 1.1rem;
      font-weight: 700;
      color: #ffffff;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .brand-title span {{
      color: var(--accent);
    }}
    .badges {{
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }}
    .badge {{
      background-color: var(--badge-bg);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 3px 10px;
      font-size: 0.75rem;
      color: var(--text-muted);
    }}
    .badge b {{
      color: var(--text);
    }}
    .controls {{
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }}
    button {{
      background-color: var(--btn-bg);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 0.8rem;
      font-weight: 500;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 6px;
      transition: all 0.15s ease-in-out;
    }}
    button:hover {{
      background-color: var(--btn-hover);
      border-color: var(--text-muted);
    }}
    button.primary {{
      background-color: var(--accent-hover);
      border-color: var(--accent);
      color: #ffffff;
    }}
    button.primary:hover {{
      background-color: var(--accent);
    }}
    #viewport {{
      flex: 1;
      width: 100%;
      height: 100%;
      position: relative;
      overflow: hidden;
      cursor: grab;
      user-select: none;
    }}
    #viewport:active {{
      cursor: grabbing;
    }}
    #diagram-wrapper {{
      transform-origin: 0 0;
      position: absolute;
      top: 0;
      left: 0;
      will-change: transform;
    }}
    #mermaid-container {{
      padding: 40px;
    }}
    #loading {{
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      font-size: 1.1rem;
      color: var(--text-muted);
    }}
    #toast {{
      position: fixed;
      bottom: 24px;
      right: 24px;
      background-color: var(--surface);
      border: 1px solid var(--accent);
      color: #ffffff;
      padding: 10px 18px;
      border-radius: 8px;
      font-size: 0.85rem;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.25s ease;
      z-index: 100;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
    }}
    #toast.show {{
      opacity: 1;
    }}
  </style>
</head>
<body>
  <header>
    <div class="brand-section">
      <div class="brand-title"><span>⚡</span> netscan Viewer</div>
      <div class="badges">
        <div class="badge"><b>{device_count}</b> Devices Discovered</div>
        <div class="badge">Subnets: <b>{subnets_str}</b></div>
        <div class="badge">Gateway: <b>{gw_str}</b></div>
        <div class="badge">{timestamp_str}</div>
      </div>
    </div>
    <div class="controls">
      <button onclick="zoomIn()" title="Zoom In">➕ In</button>
      <button onclick="zoomOut()" title="Zoom Out">➖ Out</button>
      <button onclick="resetZoom()" title="Reset View">↺ Reset</button>
      <button onclick="exportSVG()" class="primary" title="Export Vector SVG">💾 Export SVG</button>
      <button onclick="exportPNG()" class="primary" title="Export High-Resolution PNG">🖼️ Export PNG</button>
      <button onclick="copyMermaid()" title="Copy Raw Mermaid Code">📋 Copy Mermaid</button>
    </div>
  </header>

  <div id="viewport">
    <div id="loading">Rendering topology diagram...</div>
    <div id="diagram-wrapper">
      <div id="mermaid-container" class="mermaid">
{clean_mermaid}
      </div>
    </div>
  </div>

  <div id="toast"></div>

  <script>
    const rawMermaid = `{escaped_mermaid}`;

    mermaid.initialize({{
      startOnLoad: true,
      theme: 'dark',
      flowchart: {{
        curve: 'basis',
        nodeSpacing: 45,
        rankSpacing: 65,
        useMaxWidth: false
      }}
    }});

    // Pan & Zoom Engine
    let scale = 0.85;
    let panX = 40;
    let panY = 40;
    let isDragging = false;
    let startX = 0;
    let startY = 0;

    const viewport = document.getElementById('viewport');
    const wrapper = document.getElementById('diagram-wrapper');
    const loading = document.getElementById('loading');

    function updateTransform() {{
      wrapper.style.transform = `translate(${{panX}}px, ${{panY}}px) scale(${{scale}})`;
    }}

    function zoomIn() {{
      scale = Math.min(scale * 1.25, 5.0);
      updateTransform();
    }}

    function zoomOut() {{
      scale = Math.max(scale * 0.8, 0.1);
      updateTransform();
    }}

    function resetZoom() {{
      scale = 0.85;
      panX = 40;
      panY = 40;
      updateTransform();
    }}

    viewport.addEventListener('wheel', (e) => {{
      e.preventDefault();
      const zoomFactor = e.deltaY < 0 ? 1.12 : 0.89;
      const mouseX = e.clientX;
      const mouseY = e.clientY - 60; // offset header
      const newScale = Math.min(Math.max(scale * zoomFactor, 0.1), 5.0);
      panX = mouseX - (mouseX - panX) * (newScale / scale);
      panY = mouseY - (mouseY - panY) * (newScale / scale);
      scale = newScale;
      updateTransform();
    }}, {{ passive: false }});

    viewport.addEventListener('pointerdown', (e) => {{
      isDragging = true;
      startX = e.clientX - panX;
      startY = e.clientY - panY;
      viewport.setPointerCapture(e.pointerId);
    }});

    viewport.addEventListener('pointermove', (e) => {{
      if (!isDragging) return;
      panX = e.clientX - startX;
      panY = e.clientY - startY;
      updateTransform();
    }});

    viewport.addEventListener('pointerup', (e) => {{
      isDragging = false;
    }});

    // Hide loader once rendered
    document.addEventListener('DOMContentLoaded', () => {{
      setTimeout(() => {{
        if (loading) loading.style.display = 'none';
        updateTransform();
      }}, 600);
    }});

    function showToast(msg) {{
      const toast = document.getElementById('toast');
      toast.textContent = msg;
      toast.classList.add('show');
      setTimeout(() => toast.classList.remove('show'), 2500);
    }}

    // Export SVG natively from rendered DOM
    function exportSVG() {{
      const svg = document.querySelector('#mermaid-container svg');
      if (!svg) {{
        showToast('Diagram not rendered yet.');
        return;
      }}
      const serializer = new XMLSerializer();
      let source = serializer.serializeToString(svg);
      if (!source.match(/^<svg[^>]+xmlns="http\:\/\/www\.w3\.org\/2000\/svg"/)) {{
        source = source.replace(/^<svg/, '<svg xmlns="http://www.w3.org/2000/svg"');
      }}
      const blob = new Blob([source], {{ type: 'image/svg+xml;charset=utf-8' }});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'network_diagram.svg';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showToast('Exported network_diagram.svg successfully!');
    }}

    // Export High-Resolution PNG via Canvas
    function exportPNG() {{
      const svg = document.querySelector('#mermaid-container svg');
      if (!svg) {{
        showToast('Diagram not rendered yet.');
        return;
      }}
      const serializer = new XMLSerializer();
      let source = serializer.serializeToString(svg);
      if (!source.match(/^<svg[^>]+xmlns="http\:\/\/www\.w3\.org\/2000\/svg"/)) {{
        source = source.replace(/^<svg/, '<svg xmlns="http://www.w3.org/2000/svg"');
      }}
      const blob = new Blob([source], {{ type: 'image/svg+xml;charset=utf-8' }});
      const url = URL.createObjectURL(blob);
      const img = new Image();

      img.onload = () => {{
        const scaleFactor = 2; // High-DPI 2x scale
        const bbox = svg.viewBox ? svg.viewBox.baseVal : svg.getBoundingClientRect();
        const w = (bbox.width || 3840);
        const h = (bbox.height || 2160);

        const canvas = document.createElement('canvas');
        canvas.width = w * scaleFactor;
        canvas.height = h * scaleFactor;
        const ctx = canvas.getContext('2d');
        ctx.fillStyle = '#0d1117';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
        URL.revokeObjectURL(url);

        canvas.toBlob((pngBlob) => {{
          if (!pngBlob) return;
          const pngUrl = URL.createObjectURL(pngBlob);
          const a = document.createElement('a');
          a.href = pngUrl;
          a.download = 'network_diagram.png';
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(pngUrl);
          showToast('Exported network_diagram.png (High-DPI) successfully!');
        }}, 'image/png');
      }};
      img.src = url;
    }}

    function copyMermaid() {{
      navigator.clipboard.writeText(rawMermaid).then(() => {{
        showToast('Raw Mermaid syntax copied to clipboard!');
      }}).catch(() => {{
        showToast('Failed to copy to clipboard.');
      }});
    }}
  </script>
</body>
</html>
"#
        )
    }
}
