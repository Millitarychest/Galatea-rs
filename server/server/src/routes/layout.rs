use axum::response::Html;


pub fn page(title: &str, active: &str, content: &str) -> Html<String> {
    Html(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} — Galatea Server</title>
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
                <span class="icon">⊞</span> Fleet Overview
            </a>
            <a href="/events" class="{events_active}">
                <span class="icon">⚡</span> Event Feed
            </a>
        </nav>
        <div class="sidebar-footer">
            Galatea EDR — Research Project
        </div>
    </aside>
    <main class="main">
        {content}
    </main>
</div>
</body>
</html>"#,
        title = title,
        content = content,
        fleet_active = if active == "fleet" { "active" } else { "" },
        events_active = if active == "events" { "active" } else { "" },
    ))
}
