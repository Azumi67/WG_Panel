
(() => {
  const targetId = 'particles-bg';

  function particleConfig(color) {
    return {
      particles: {
        number: { value: 60, density: { enable: true, value_area: 900 } },
        color: { value: color },
        shape: { type: "circle" },
        opacity: { value: 0.35 },
        size: { value: 3, random: true },
        line_linked: { enable: true, distance: 140, color: color, opacity: 0.25, width: 1 },
        move: { enable: true, speed: 1.1, out_mode: "out" }
      },
      interactivity: {
        detect_on: "canvas",
        events: { onhover: { enable: true, mode: "grab" }, resize: true },
        modes: { grab: { distance: 160, line_linked: { opacity: 0.4 } } }
      },
      retina_detect: true
    };
  }

  function currentColor() {
    return getComputedStyle(document.documentElement)
      .getPropertyValue('--particles').trim() || "#b6c1d8";
  }

  function initParticles() {
    if (window.pJSDom && window.pJSDom.length) {
      window.pJSDom[0].pJS.fn.vendors.destroypJS();
      window.pJSDom = [];
    }
    particlesJS(targetId, particleConfig(currentColor()));
  }

  initParticles();

  const observer = new MutationObserver(() => initParticles());
  observer.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });

})();
