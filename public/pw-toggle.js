(function () {
  "use strict";

  const SVG_NS = "http://www.w3.org/2000/svg";

  function makeSvg(paths) {
    const svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("width", "18");
    svg.setAttribute("height", "18");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "1.9");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    svg.setAttribute("aria-hidden", "true");
    paths.forEach((def) => {
      const el = document.createElementNS(SVG_NS, def.tag);
      Object.entries(def.attrs).forEach(([k, v]) => el.setAttribute(k, v));
      svg.appendChild(el);
    });
    return svg;
  }

  function createEyeIcon() {
    return makeSvg([
      { tag: "path", attrs: { d: "M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z" } },
      { tag: "circle", attrs: { cx: "12", cy: "12", r: "3" } }
    ]);
  }

  function createEyeOffIcon() {
    return makeSvg([
      { tag: "path", attrs: { d: "M9.88 9.88a3 3 0 1 0 4.24 4.24" } },
      { tag: "path", attrs: { d: "M10.73 5.08A10.43 10.43 0 0 1 12 5c6.5 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68" } },
      { tag: "path", attrs: { d: "M6.61 6.61A13.526 13.526 0 0 0 2 12s3.5 7 10 7a9.74 9.74 0 0 0 5.39-1.61" } },
      { tag: "line", attrs: { x1: "2", y1: "2", x2: "22", y2: "22" } }
    ]);
  }

  function enhanceInput(input) {
    if (!input || input.dataset.pwEnhanced === "1") return;
    if (input.type !== "password") return;
    if (input.parentElement && input.parentElement.classList.contains("pw-wrap")) {
      input.dataset.pwEnhanced = "1";
      return;
    }

    input.dataset.pwEnhanced = "1";

    const wrap = document.createElement("span");
    wrap.className = "pw-wrap";
    input.parentNode.insertBefore(wrap, input);
    wrap.appendChild(input);

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "pw-toggle";
    btn.setAttribute("aria-label", "Show password");
    btn.setAttribute("aria-pressed", "false");
    btn.title = "Show password";
    btn.appendChild(createEyeIcon());
    wrap.appendChild(btn);

    function setVisible(visible) {
      input.type = visible ? "text" : "password";
      btn.setAttribute("aria-pressed", visible ? "true" : "false");
      btn.setAttribute("aria-label", visible ? "Hide password" : "Show password");
      btn.title = visible ? "Hide password" : "Show password";
      btn.classList.toggle("is-visible", visible);
      btn.replaceChildren(visible ? createEyeOffIcon() : createEyeIcon());
    }

    btn.addEventListener("click", () => {
      setVisible(input.type === "password");
      input.focus({ preventScroll: true });
    });

    if (input.form) {
      input.form.addEventListener("reset", () => setVisible(false));
    }
  }

  function enhancePasswordFields(root) {
    const scope = root && root.querySelectorAll ? root : document;
    if (scope.matches && scope.matches('input[type="password"]')) {
      enhanceInput(scope);
    }
    scope.querySelectorAll('input[type="password"]').forEach(enhanceInput);
  }

  function init() {
    enhancePasswordFields(document);
    if (typeof MutationObserver !== "undefined" && document.body) {
      const observer = new MutationObserver((mutations) => {
        for (const m of mutations) {
          for (const node of m.addedNodes) {
            if (node.nodeType === 1) enhancePasswordFields(node);
          }
        }
      });
      observer.observe(document.body, { childList: true, subtree: true });
    }
  }

  window.enhancePasswordFields = enhancePasswordFields;
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
