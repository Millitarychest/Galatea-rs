use axum::response::Html;

pub fn page(title: &str, active: &str, registration_secret: &str, content: &str) -> Html<String> {
    let escaped_secret = escape_html(registration_secret);

    Html(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - Galatea Server</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
<div class="layout">
    <aside class="sidebar">
        <div class="sidebar-header">
            <div class="logo">G</div>
            <div>
                <h1>Galatea</h1>
                <span class="version">Server v0.1.0</span>
            </div>
        </div>
        <nav class="sidebar-nav">
            <a href="/" class="{fleet_active}">
                <span class="icon">[+]</span> Fleet Overview
            </a>
            <a href="/events" class="{events_active}">
                <span class="icon">[!]</span> Event Feed
            </a>
        </nav>
        <div class="theme-control">
            <label for="theme-select">Theme</label>
            <select id="theme-select" aria-label="Select theme">
                <option value="dark">Dark</option>
                <option value="light">Light</option>
                <option value="defender">Defender</option>
                <option value="treadstone">Treadstone</option>
            </select>
            <button type="button" class="secret-trigger" data-modal-open="agent-secret-modal">
                Agent Registration Secret
            </button>
        </div>
        <div class="sidebar-footer">
            Galatea EDR - Research Project
        </div>
    </aside>
    <main class="main">
        {content}
    </main>
</div>
<div id="agent-secret-modal" class="modal-overlay" hidden>
    <div class="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="agent-secret-title">
        <div class="modal-header">
            <h3 id="agent-secret-title">Agent Registration Secret</h3>
            <button type="button" class="modal-close" data-modal-close="agent-secret-modal" aria-label="Close">x</button>
        </div>
        <p class="modal-description">Use this secret when enrolling new agents.</p>
        <pre class="modal-secret mono">{registration_secret}</pre>
        <div class="modal-actions">
            <button type="button" class="modal-close-button" data-modal-close="agent-secret-modal">Close</button>
        </div>
    </div>
</div>
<script src="/static/js/theme.js"></script>
<script>
(() => {{
    const modalId = "agent-secret-modal";
    const modal = document.getElementById(modalId);
    if (!modal) {{
        return;
    }}

    const openers = document.querySelectorAll('[data-modal-open="' + modalId + '"]');
    const closers = modal.querySelectorAll('[data-modal-close="' + modalId + '"]');
    const openModal = () => {{
        modal.hidden = false;
    }};
    const closeModal = () => {{
        modal.hidden = true;
    }};

    openers.forEach((button) => {{
        button.addEventListener("click", openModal);
    }});
    closers.forEach((button) => {{
        button.addEventListener("click", closeModal);
    }});
    modal.addEventListener("click", (event) => {{
        if (event.target === modal) {{
            closeModal();
        }}
    }});
    window.addEventListener("keydown", (event) => {{
        if (event.key === "Escape" && !modal.hidden) {{
            closeModal();
        }}
    }});
}})();
</script>
</body>
</html>"#,
        title = title,
        content = content,
        registration_secret = escaped_secret,
        fleet_active = if active == "fleet" { "active" } else { "" },
        events_active = if active == "events" { "active" } else { "" },
    ))
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
