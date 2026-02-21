(() => {
    const root = document.documentElement;
    const select = document.getElementById("theme-select");
    const storageKey = "galatea-theme";
    const themes = new Set(["light", "dark", "defender", "treadstone"]);
    const preferred = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light";
    const stored = localStorage.getItem(storageKey);
    const theme = themes.has(stored) ? stored : preferred;

    root.setAttribute("data-theme", theme);

    if (select) {
        select.value = theme;
        select.addEventListener("change", (event) => {
            const nextTheme = event.target.value;
            if (!themes.has(nextTheme)) {
                return;
            }
            root.setAttribute("data-theme", nextTheme);
            localStorage.setItem(storageKey, nextTheme);
        });
    }
})();
